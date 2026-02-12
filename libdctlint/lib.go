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

	gonet "github.com/THREATINT/go-net"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
)

const (
	max16b = 1<<16 - 1
	max31b = 1<<31 - 1
)

// GetAndCheckTemplate is used in dctweb. Do not use applications
// outside of this project.
func (conf *Conf) GetAndCheckTemplate(f *bufio.Reader) (internal.Template, exitvals.CheckSeverity) {
	conf.SetLogger(log.With().Str("template", conf.fileName).Logger())
	conf.tlog.Debug().Msg("starting template check")

	// Decode json
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var template internal.Template
	err := decoder.Decode(&template)
	if err != nil {
		conf.tlog.Error().Err(err).EmbedObject(internal.DCTL0003).Msg("")
		return template, exitvals.CheckFatal
	}
	exitVal := conf.checkTemplate(template)
	return template, exitVal
}

// CheckTemplate takes bufio.Reader as an argument and will run template
// checks according to the Conf configuration. Please remember to
// set conf.fileName appropriately before calling this function to avoid
// confusing results.
func (conf *Conf) CheckTemplate(f *bufio.Reader) exitvals.CheckSeverity {
	// A single template check init
	_, exitVal := conf.GetAndCheckTemplate(f)
	return exitVal
}

func (conf *Conf) checkTemplate(template internal.Template) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK
	// Ensure ID fields use valid characters
	if checkInvalidChars(template.ProviderID) {
		conf.tlog.Error().Str("providerId", template.ProviderID).EmbedObject(internal.DCTL1002).Msg("")
		exitVal |= exitvals.CheckError
	}
	if checkInvalidChars(template.ServiceID) {
		conf.tlog.Error().Str("serviceId", template.ServiceID).EmbedObject(internal.DCTL1002).Msg("")
		exitVal |= exitvals.CheckError
	}

	// Check 6.11.2. File naming requirements
	if conf.fileName != "/dev/stdin" {
		expected := strings.ToLower(template.ProviderID) + "." + strings.ToLower(template.ServiceID) + ".json"
		if filepath.Base(conf.fileName) != expected {
			conf.tlog.Error().Str("expected", expected).EmbedObject(internal.DCTL1003).Msg("")
			exitVal |= exitvals.CheckError
		}
	}

	// Detect ID collisions _across multiple_ templates
	if _, found := conf.collision[template.ProviderID+"/"+template.ServiceID]; found {
		conf.tlog.Error().
			Str("providerId", template.ProviderID).
			Str("serviceId", template.ServiceID).
			EmbedObject(internal.DCTL1004).Msg("")
		exitVal |= exitvals.CheckError
	}
	conf.collision[template.ProviderID+"/"+template.ServiceID] = true

	// Check 'validate:' fields in internal/json.go definitions
	validate := validator.New(validator.WithRequiredStructEnabled())
	err := validate.Struct(template)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			conf.tlog.Warn().Err(err).EmbedObject(internal.DCTL1005).Msg("")
			exitVal |= exitvals.CheckWarn
		}
	}

	// and validate the records
	for _, record := range template.Records {
		err := validate.Struct(record)
		if err != nil {
			for _, err := range err.(validator.ValidationErrors) {
				conf.tlog.Warn().Err(err).EmbedObject(internal.DCTL1005).Msg("")
				exitVal |= exitvals.CheckWarn
			}
		}
	}

	// Field checks provided by this file
	if template.Version == 0 {
		conf.tlog.Info().EmbedObject(internal.DCTL1006).Msg("")
		exitVal |= exitvals.CheckInfo
	}
	if template.Shared && !template.SharedProviderName {
		conf.tlog.Error().EmbedObject(internal.DCTL1007).Msg("")
		exitVal |= exitvals.CheckError
		// Override to ensure settings in pretty-print output are correct
		template.Shared = true
		template.SharedProviderName = true
	}
	if !template.Shared && template.SharedProviderName {
		conf.tlog.Info().EmbedObject(internal.DCTL1008).Msg("")
		exitVal |= exitvals.CheckInfo
		// Override to ensure settings in pretty-print output are correct
		template.Shared = true
		template.SharedProviderName = true
	}

	if isVariable(template.ProviderName) {
		conf.tlog.Error().Str("providerName", template.ProviderName).EmbedObject(internal.DCTL1009).Msg("")
		exitVal |= exitvals.CheckError
	}
	if isVariable(template.ServiceName) {
		conf.tlog.Error().Str("serviceName", template.ServiceName).EmbedObject(internal.DCTL1009).Msg("")
		exitVal |= exitvals.CheckError
	}

	// Logo url reachability check
	if err := conf.isUnreachable(template.Logo); err != nil {
		conf.tlog.Warn().Err(err).Str("logoUrl", template.Logo).EmbedObject(internal.DCTL1010).Msg("")
		exitVal |= exitvals.CheckWarn
	}

	if err := checkFQDN(template.SyncPubKeyDomain); err != nil {
		conf.tlog.Error().Err(err).Str("SyncPubKeyDomain", template.SyncPubKeyDomain).EmbedObject(internal.DCTL1022).Msg("")
		exitVal |= exitvals.CheckWarn
	}

	if err := conf.checkSyncRedirectDomain(template.SyncRedirectDomain); err != nil {
		conf.tlog.Error().Err(err).Str("SyncRedirectDomain", template.SyncRedirectDomain).EmbedObject(internal.DCTL1022).Msg("")
		exitVal |= exitvals.CheckWarn
	}

	if template.WarnPhishing && template.SyncPubKeyDomain != "" {
		conf.tlog.Info().EmbedObject(internal.DCTL1028).Msg("")
		exitVal |= exitvals.CheckInfo
	}

	if !template.SyncBlock && template.SyncPubKeyDomain == "" {
		conf.tlog.Info().EmbedObject(internal.DCTL1029).Msg("")
		exitVal |= exitvals.CheckInfo
	}

	// DNS provider specific checks
	if conf.cloudflare {
		conf.tlog.Debug().Msg("performing Cloudflare checks")
		exitVal |= conf.cloudflareTemplateChecks(template)
	}

	// Template records checks
	if len(template.Records) == 0 {
		conf.tlog.Error().EmbedObject(internal.DCTL1030).Msg("")
		exitVal |= exitvals.CheckError
	}
	conflictingTypes := make(map[string]string)
	conf.duplicates = make(map[uint64]bool)
	for rnum, record := range template.Records {
		exitVal |= conf.checkRecord(template, rnum, &record, conflictingTypes)
		template.Records[rnum] = record
	}

	// Pretty printing and/or inplace write output
	if conf.prettyPrint || conf.inplace {
		if conf.increment {
			template.Version++
		}

		// Remove white spaces, see DCTL1026
		template.SyncRedirectDomain = internal.StripSpaces(template.SyncRedirectDomain)

		// Convert to json
		marshaled, err := json.Marshal(template)
		if err != nil {
			conf.tlog.Error().Err(err).EmbedObject(internal.DCTL0003).Msg("")
			return exitVal | exitvals.CheckError
		}

		// Make output pretty
		var out bytes.Buffer
		err = json.Indent(&out, marshaled, "", strings.Repeat(" ", int(conf.indent)))
		if err != nil {
			conf.tlog.Error().Err(err).EmbedObject(internal.DCTL0003).Msg("")
			return exitVal | exitvals.CheckError
		}
		_, err = fmt.Fprintf(&out, "\n")
		if err != nil {
			conf.tlog.Error().Err(err).Msg("could not print to output")
			exitVal += exitvals.CheckFatal
		}

		// Decide where to write
		if conf.inplace {
			exitVal |= conf.writeBack(out)
		} else {
			_, err = out.WriteTo(os.Stdout)
			if err != nil {
				conf.tlog.Error().Err(err).EmbedObject(internal.DCTL0004).Msg("")
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
	outfile, err := os.CreateTemp("./", path.Base(conf.fileName))
	if err != nil {
		conf.tlog.Warn().Err(err).EmbedObject(internal.DCTL0005).Msg("")
		return exitvals.CheckError
	}
	defer func() {
		err := outfile.Close()
		if err != nil {
			conf.tlog.Error().Err(err).Msg("could not close output file")
		}
	}()

	// Write to temporary file
	writer := bufio.NewWriter(outfile)
	_, err = out.WriteTo(writer)
	if err != nil {
		conf.tlog.Warn().Err(err).EmbedObject(internal.DCTL0004).Msg("")
		return exitvals.CheckError
	}
	err = writer.Flush()
	if err != nil {
		conf.tlog.Error().Err(err).Msg("could not write file")
		return exitvals.CheckFatal
	}

	// Move temporary file where the original file is
	err = os.Rename(outfile.Name(), conf.fileName)
	if err != nil {
		conf.tlog.Warn().Err(err).EmbedObject(internal.DCTL0006).Msg("")
		return exitvals.CheckWarn
	}
	conf.tlog.Debug().Str("tmpfile", outfile.Name()).Msg("updated")
	return exitvals.CheckOK
}

func isVariable(s string) bool {
	return strings.Count(s, "%") > 1
}

func (conf *Conf) checkSyncRedirectDomain(srd string) (err error) {
	srdList := strings.Split(srd, ",")
	for i := range srdList {
		trimmed := strings.TrimSpace(srdList[i])
		if trimmed != srdList[i] {
			conf.tlog.Warn().Str("domain", srdList[i]).EmbedObject(internal.DCTL1026).Msg("")
		}
		e := checkFQDN(trimmed)
		if e != nil && err == nil {
			err = e
		}
	}
	return err
}

func checkFQDN(fqdn string) error {
	if fqdn == "" {
		return nil
	}
	if gonet.IsFQDN(fqdn) {
		fqdn = gonet.DomainFromFqdn(fqdn)
	}
	if !gonet.IsDomain(fqdn) {
		return fmt.Errorf("failed go-net.IsFQDN() test: '%s'", fqdn)
	}
	if !strings.ContainsRune(fqdn, '.') {
		return fmt.Errorf("tld is not allowed")
	}
	return nil
}

func (conf *Conf) cloudflareTemplateChecks(template internal.Template) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK
	if template.SyncBlock {
		conf.tlog.Error().EmbedObject(internal.DCTL5000).Msg("")
		exitVal |= exitvals.CheckError
	}
	if template.SyncPubKeyDomain == "" {
		conf.tlog.Error().EmbedObject(internal.DCTL5001).Msg("")
		exitVal |= exitvals.CheckError
	}
	if template.SharedServiceName {
		conf.tlog.Info().EmbedObject(internal.DCTL5002).Msg("")
		exitVal |= exitvals.CheckInfo
	}
	if template.SyncRedirectDomain != "" {
		conf.tlog.Info().EmbedObject(internal.DCTL5003).Msg("")
		exitVal |= exitvals.CheckInfo
	}
	if template.MultiInstance {
		conf.tlog.Info().EmbedObject(internal.DCTL5004).Msg("")
		exitVal |= exitvals.CheckInfo
	}
	if template.WarnPhishing {
		conf.tlog.Info().EmbedObject(internal.DCTL5005).Msg("")
		exitVal |= exitvals.CheckInfo
	}
	if template.HostRequired {
		conf.tlog.Info().EmbedObject(internal.DCTL5006).Msg("")
		exitVal |= exitvals.CheckInfo
	}
	return exitVal
}
