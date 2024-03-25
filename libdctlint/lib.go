// Package libdctlint provides a library to check/lint Domain Connect
// service provider template.
//
// Check results are communicated to humans with zerolog messages, that one
// is recommended to configure in software calling this library.
package libdctlint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	max16b = 1<<16 - 1
	max31b = 1<<31 - 1
)

// Conf holds template checking instructions. The field type FileName must
// be updated each time CheckTemplate() is called to match with the
// bufio.Reader argument.
type Conf struct {
	FileName    string
	tlog        zerolog.Logger
	collision   map[string]bool
	checkLogos  bool
	cloudflare  bool
	inplace     bool
	increment   bool
	prettyPrint bool
}

// NewConf will create template check configuration.
//
// The argument checkLogos will test if a logoUrl in template is reachable,
// this requires network access can slow down the check.
//
// The argument cloudflare will enable Cloudflare specific tests.
//
// The argument inplace will write back the file with some automatic issue
// corrections, re-indent, and uniform order of the struct fields. When
// CheckTemplate() bufio.Reader is stdin or some other non-writable io
// stream it is best to hardcode inplace false.
//
// The argument prettyPrint will do the same as inplace, but will output
// print out to standard out. When both prettyPrint and inplace defined the
// library will prefer applying inplace.
func NewConf(checkLogos, cloudflare, inplace, increment, prettyPrint bool) Conf {
	return Conf{
		collision:   make(map[string]bool),
		checkLogos:  checkLogos,
		cloudflare:  cloudflare,
		inplace:     inplace,
		increment:   increment,
		prettyPrint: prettyPrint,
	}
}

// GetAndCheckTemplate is used in dctweb. Do not use applications
// outside of this project.
func (conf *Conf) GetAndCheckTemplate(f *bufio.Reader) (internal.Template, exitvals.CheckSeverity) {
	conf.tlog = log.With().Str("template", conf.FileName).Logger()
	internal.SetLogger(conf.tlog)
	conf.tlog.Debug().Msg("starting template check")

	// Decode json
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var template internal.Template
	err := decoder.Decode(&template)
	exitVal := internal.GetUnmarshalStatus()
	if err != nil {
		conf.tlog.Error().Err(err).Msg("json decode error")
		return template, exitvals.CheckFatal
	}
	exitVal |= conf.checkTemplate(f, template)
	return template, exitVal
}

// CheckTemplate takes bufio.Reader as an argument and will run template
// checks according to the Conf configuration. Please remember to
// set conf.FileName appropriately before calling this function to avoid
// confusing results.
func (conf *Conf) CheckTemplate(f *bufio.Reader) exitvals.CheckSeverity {
	// A single template check init
	_, exitVal := conf.GetAndCheckTemplate(f)
	return exitVal
}

func (conf *Conf) checkTemplate(f *bufio.Reader, template internal.Template) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK
	// Ensure ID fields use valid characters
	if checkInvalidChars(template.ProviderID) {
		conf.tlog.Error().Str("providerId", template.ProviderID).Msg("providerId contains invalid characters")
		exitVal |= exitvals.CheckError
	}
	if checkInvalidChars(template.ServiceID) {
		conf.tlog.Error().Str("serviceId", template.ServiceID).Msg("serviceId contains invalid characters")
		exitVal |= exitvals.CheckError
	}

	// Check 6.11.2. File naming requirements
	if strings.ToLower(template.ProviderID)+"."+strings.ToLower(template.ServiceID)+".json" != filepath.Base(conf.FileName) {
		conf.tlog.Error().Str("expected", strings.ToLower(template.ProviderID)+"."+strings.ToLower(template.ServiceID)+".json").Msg("file name does not use required pattern")
		exitVal |= exitvals.CheckError
	}

	// Detect ID collisions _across multiple_ templates
	if _, found := conf.collision[template.ProviderID+"/"+template.ServiceID]; found {
		conf.tlog.Error().
			Str("providerId", template.ProviderID).
			Str("serviceId", template.ServiceID).
			Msg("duplicate provierId + serviceId detected")
		exitVal |= exitvals.CheckError
	}
	conf.collision[template.ProviderID+"/"+template.ServiceID] = true

	// Check 'validate:' fields in internal/json.go definitions
	Validator := validator.New()
	err := Validator.Struct(template)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			conf.tlog.Warn().Err(err).Msg("template field validation")
			exitVal |= exitvals.CheckWarn
		}
	}

	// Field checks provided by this file
	if template.Version < 0 {
		conf.tlog.Info().Msg("use of negative version number is not recommended")
		exitVal |= exitvals.CheckInfo
	}
	if template.Shared && !template.SharedProviderName {
		conf.tlog.Error().Msg("shared flag is deprecated, use sharedProviderName as well")
		exitVal |= exitvals.CheckError
		// Override to ensure settings in pretty-print output are correct
		template.Shared = true
		template.SharedProviderName = true
	}
	if !template.Shared && template.SharedProviderName {
		conf.tlog.Info().Msg("sharedProviderName is in use, but shared backward compatibility is not set")
		exitVal |= exitvals.CheckInfo
		// Override to ensure settings in pretty-print output are correct
		template.Shared = true
		template.SharedProviderName = true
	}

	if isVariable(template.ProviderName) {
		conf.tlog.Error().Msg("providerName must not be variable")
		exitVal |= exitvals.CheckError
	}
	if isVariable(template.ServiceName) {
		conf.tlog.Error().Msg("serviceName must not be variable")
		exitVal |= exitvals.CheckError
	}

	// Logo url reachability check
	if err := conf.isUnreachable(template.Logo); err != nil {
		conf.tlog.Warn().Err(err).Str("logoUrl", template.Logo).Msg("logo check failed")
		exitVal |= exitvals.CheckWarn
	}

	// DNS provider specific checks
	if conf.cloudflare {
		conf.tlog.Debug().Msg("performing Cloudflare checks")
		exitVal |= conf.cloudflareTemplateChecks(template)
	}

	// Template records checks
	conflictingTypes := make(map[string]string)
	for rnum, record := range template.Records {
		exitVal |= conf.checkRecord(template, rnum, record, conflictingTypes)
	}

	// Pretty printing and/or inplace write output
	if conf.prettyPrint || conf.inplace {
		if conf.increment {
			template.Version++
		}
		// Convert to json
		marshaled, err := json.Marshal(template)
		if err != nil {
			conf.tlog.Error().Err(err).Msg("json marshaling failed")
			return exitVal | exitvals.CheckError
		}

		// Make output pretty
		var out bytes.Buffer
		err = json.Indent(&out, marshaled, "", "    ")
		if err != nil {
			conf.tlog.Error().Err(err).Msg("json indenting failed")
			return exitVal | exitvals.CheckError
		}
		fmt.Fprintf(&out, "\n")

		// Decide where to write
		if conf.inplace {
			exitVal |= conf.writeBack(out)
		} else {
			_, err = out.WriteTo(os.Stdout)
			if err != nil {
				conf.tlog.Error().Err(err).Msg("write failed")
				exitVal |= exitvals.CheckError
			}
		}
	}

	conf.tlog.Debug().Uint32("exitVal", uint32(exitVal)).Msg("template check done")
	return exitVal
}

const validChars = "-.0123456789_abcdefghijklmnopqrstuvwxyz"

func checkInvalidChars(s string) bool {
	for _, char := range s {
		if !strings.Contains(validChars, strings.ToLower(string(char))) {
			return true
		}
	}
	return false
}

func (conf *Conf) isUnreachable(logoURL string) error {
	if !conf.checkLogos || logoURL == "" {
		return nil
	}
	conf.tlog.Debug().Str("url", logoURL).Msg("checking logo url")
	resp, err := http.Get(logoURL)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status %d", resp.StatusCode)
	}
	return nil
}

func (conf *Conf) writeBack(out bytes.Buffer) exitvals.CheckSeverity {
	// Create temporary file
	outfile, err := os.CreateTemp("./", path.Base(conf.FileName))
	if err != nil {
		conf.tlog.Warn().Err(err).Msg("could not create temporary file")
		return exitvals.CheckError
	}
	defer outfile.Close()

	// Write to temporary file
	writer := bufio.NewWriter(outfile)
	_, err = out.WriteTo(writer)
	if err != nil {
		conf.tlog.Warn().Err(err).Msg("could write to temporary file")
		return exitvals.CheckError
	}
	writer.Flush()

	// Move temporary file where the original file is
	err = os.Rename(outfile.Name(), conf.FileName)
	if err != nil {
		conf.tlog.Warn().Err(err).Msg("could not move template back inplace")
		return exitvals.CheckWarn
	}
	conf.tlog.Debug().Str("tmpfile", outfile.Name()).Msg("updated")
	return exitvals.CheckOK
}

func isVariable(s string) bool {
	return strings.Count(s, "%") > 1
}

func (conf *Conf) cloudflareTemplateChecks(template internal.Template) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK
	if template.SyncBlock {
		conf.tlog.Error().Msg("Cloudflare does not support syncBlock")
		exitVal |= exitvals.CheckError
	}
	if template.SyncPubKeyDomain == "" {
		conf.tlog.Error().Msg("Cloudflare requires syncPubKeyDomain")
		exitVal |= exitvals.CheckError
	}
	if template.SharedServiceName {
		conf.tlog.Info().Msg("Cloudflare does not support sharedServiceName")
		exitVal |= exitvals.CheckInfo
	}
	if template.SyncRedirectDomain != "" {
		conf.tlog.Info().Msg("Cloudflare does not support syncRedirectDomain")
		exitVal |= exitvals.CheckInfo
	}
	if template.MultiInstance {
		conf.tlog.Info().Msg("Cloudflare does not support multiInstance")
		exitVal |= exitvals.CheckInfo
	}
	if template.WarnPhishing {
		conf.tlog.Info().Msg("Cloudflare does not use warnPhishing because syncPubKeyDomain is required")
		exitVal |= exitvals.CheckInfo
	}
	if template.HostRequired {
		conf.tlog.Info().Msg("Cloudflare does not support hostRequired")
		exitVal |= exitvals.CheckInfo
	}
	return exitVal
}
