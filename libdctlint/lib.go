// Package libdctlint provides a library to check/lint Domain Connect
// service provider template.
//
// Check results are communicated via zerolog messages in interactive mode,
// or via a DCTLMessage list when library mode is active (SetLib(true)).
package libdctlint

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"

	gonet "github.com/THREATINT/go-net"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	max16b = 1<<16 - 1
	max31b = 1<<31 - 1
)

// ProjectVersion returns the dc-template-linter project version number.
func ProjectVersion() uint {
	return uint(internal.ProjectVersion)
}

// captureWriter is a zerolog-compatible io.Writer that parses each JSON log
// line emitted in library mode and appends it to conf.messages when it
// contains a DCTL code field.
type captureWriter struct {
	conf *Conf
}

func (cw *captureWriter) Write(p []byte) (int, error) {
	var parsed struct {
		Code  string `json:"code"`
		Level string `json:"level"`
	}
	msg := strings.TrimRight(string(p), "\n")
	if json.Unmarshal(p, &parsed) == nil && parsed.Code != "" {
		var code uint16
		if _, err := fmt.Sscanf(parsed.Code, "DCTL%04d", &code); err == nil {
			level, _ := zerolog.ParseLevel(parsed.Level)
			cw.conf.messages = append(cw.conf.messages, DCTLMessage{
				Code:    internal.DCTL(code),
				Level:   level,
				Message: msg,
			})
		}
	}
	return len(p), nil
}

// emit logs the given DCTL code at its defined level using logger and returns
// the corresponding exitvals.CheckSeverity bit for the caller to OR into its
// local exitVal. fn may be nil or a function that adds extra fields to the
// zerolog event before it is dispatched.
//
// In library mode the event is written to the captureWriter (set up by
// GetAndCheckTemplate) so it is stored in conf.messages; no output reaches
// the zerolog global logger.
func (conf *Conf) emit(logger zerolog.Logger, dctl internal.DCTL, fn func(*zerolog.Event) *zerolog.Event) exitvals.CheckSeverity {
	e := logger.WithLevel(dctl.Level())
	if fn != nil {
		e = fn(e)
	}
	e.EmbedObject(dctl).Msg("")
	return dctl.Severity()
}

// GetAndCheckTemplate is used in dctweb. Do not use applications
// outside of this project.
func (conf *Conf) GetAndCheckTemplate(f *bufio.Reader) (internal.Template, exitvals.CheckSeverity) {
	// Reset per-call message list
	conf.messages = nil

	if conf.lib {
		cw := &captureWriter{conf: conf}
		conf.SetLogger(zerolog.New(cw).With().Str("template", conf.fileName).Logger())
	} else {
		conf.SetLogger(log.With().Str("template", conf.fileName).Logger())
	}
	conf.tlog.Debug().Msg("starting template check")

	// Decode json
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var template internal.Template
	err := decoder.Decode(&template)
	if err != nil {
		conf.emit(conf.tlog, internal.DCTL0003, func(e *zerolog.Event) *zerolog.Event {
			return e.Err(err)
		})
		return template, exitvals.CheckFatal
	}
	exitVal := conf.checkTemplate(template)
	return template, exitVal
}

// CheckTemplate takes bufio.Reader as an argument and will run template
// checks according to the Conf configuration. Please remember to
// set conf.fileName appropriately before calling this function to avoid
// confusing results.
//
// In library mode (SetLib(true)) all DCTL messages are stored and accessible
// via GetMessages() after this call returns.
func (conf *Conf) CheckTemplate(f *bufio.Reader) exitvals.CheckSeverity {
	// A single template check init
	_, exitVal := conf.GetAndCheckTemplate(f)
	return exitVal
}

func (conf *Conf) checkTemplate(template internal.Template) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK
	// Ensure ID fields use valid characters
	if checkInvalidChars(template.ProviderID) {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1002, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("providerId", template.ProviderID)
		})
	}
	if checkInvalidChars(template.ServiceID) {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1002, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("serviceId", template.ServiceID)
		})
	}

	// Check 6.11.2. File naming requirements
	if conf.fileName != "/dev/stdin" {
		expected := strings.ToLower(template.ProviderID) + "." + strings.ToLower(template.ServiceID) + ".json"
		if filepath.Base(conf.fileName) != expected {
			exitVal |= conf.emit(conf.tlog, internal.DCTL1003, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("expected", expected)
			})
		}
	}

	// Detect ID collisions _across multiple_ templates
	if _, found := conf.collision[template.ProviderID+"/"+template.ServiceID]; found {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1004, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("providerId", template.ProviderID).Str("serviceId", template.ServiceID)
		})
	}
	conf.collision[template.ProviderID+"/"+template.ServiceID] = true

	// Check 'validate:' fields in internal/json.go definitions
	validate := validator.New(validator.WithRequiredStructEnabled())
	err := validate.Struct(template)
	if err != nil {
		for _, verr := range err.(validator.ValidationErrors) {
			exitVal |= conf.emit(conf.tlog, internal.DCTL1005, func(e *zerolog.Event) *zerolog.Event {
				return e.Err(verr)
			})
		}
	}

	// and validate the records
	for _, record := range template.Records {
		err := validate.Struct(record)
		if err != nil {
			for _, verr := range err.(validator.ValidationErrors) {
				exitVal |= conf.emit(conf.tlog, internal.DCTL1005, func(e *zerolog.Event) *zerolog.Event {
					return e.Err(verr)
				})
			}
		}
	}

	// Field checks provided by this file
	if template.Version == 0 {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1006, nil)
	}
	if template.Shared && !template.SharedProviderName {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1007, nil)
		// Override to ensure settings in pretty-print output are correct
		template.Shared = true
		template.SharedProviderName = true
	}
	if !template.Shared && template.SharedProviderName {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1008, nil)
		// Override to ensure settings in pretty-print output are correct
		template.Shared = true
		template.SharedProviderName = true
	}

	if isVariable(template.ProviderName) {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1009, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("providerName", template.ProviderName)
		})
	}
	if isVariable(template.ServiceName) {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1009, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("serviceName", template.ServiceName)
		})
	}

	// Logo url reachability check
	if err := conf.isUnreachable(template.Logo); err != nil {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1010, func(e *zerolog.Event) *zerolog.Event {
			return e.Err(err).Str("logoUrl", template.Logo)
		})
	}

	if err := checkFQDN(template.SyncPubKeyDomain); err != nil {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1022, func(e *zerolog.Event) *zerolog.Event {
			return e.Err(err).Str("SyncPubKeyDomain", template.SyncPubKeyDomain)
		})
	}

	if err := conf.checkSyncRedirectDomain(template.SyncRedirectDomain); err != nil {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1022, func(e *zerolog.Event) *zerolog.Event {
			return e.Err(err).Str("SyncRedirectDomain", template.SyncRedirectDomain)
		})
	}

	if template.WarnPhishing && template.SyncPubKeyDomain != "" {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1028, nil)
	}

	if !template.SyncBlock && template.SyncPubKeyDomain == "" {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1029, nil)
	}

	// DNS provider specific checks
	if conf.cloudflare {
		conf.tlog.Debug().Msg("performing Cloudflare checks")
		exitVal |= conf.cloudflareTemplateChecks(template)
	}

	// Template records checks
	if len(template.Records) == 0 {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1030, nil)
	}
	conflictingTypes := make(map[string]string)
	conf.duplicates = make(map[uint64]bool)
	groupIdTrack := make(map[string]struct{})
	for rnum, record := range template.Records {
		exitVal |= conf.checkRecord(template, rnum, &record, conflictingTypes)
		template.Records[rnum] = record
		groupIdTrack[record.GroupID] = struct{}{}
	}

	if conf.sharedvar != "" {
		exitVal |= conf.emit(conf.tlog, internal.DCTL1039, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("variable", conf.sharedvar)
		})
	}

	// Is the same groupId defined for all records. No groupId is fine
	if len(groupIdTrack) == 1 {
		_, isEmpty := groupIdTrack[""]
		if !isEmpty {
			for groupId := range groupIdTrack {
				exitVal |= conf.emit(conf.tlog, internal.DCTL1031, func(e *zerolog.Event) *zerolog.Event {
					return e.Str("groupId", groupId)
				})
			}
		}
	} else {
		if _, isEmpty := groupIdTrack[""]; isEmpty {
			exitVal |= conf.emit(conf.tlog, internal.DCTL1032, nil)
		}
	}

	// Check hostRequired constraint: must have NS or CNAME record with host @ or empty
	if template.HostRequired {
		hasRequiredRecord := false
		for _, record := range template.Records {
			if (record.Type == "NS" || record.Type == "CNAME") && (record.Host == "@" || record.Host == "") {
				hasRequiredRecord = true
				break
			}
		}
		if !hasRequiredRecord {
			exitVal |= conf.emit(conf.tlog, internal.DCTL1037, nil)
		}
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
			conf.emit(conf.tlog, internal.DCTL0003, func(e *zerolog.Event) *zerolog.Event {
				return e.Err(err)
			})
			return exitVal | exitvals.CheckError
		}

		// Make output pretty
		var out bytes.Buffer
		err = json.Indent(&out, marshaled, "", strings.Repeat(" ", int(conf.indent)))
		if err != nil {
			conf.emit(conf.tlog, internal.DCTL0003, func(e *zerolog.Event) *zerolog.Event {
				return e.Err(err)
			})
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
				conf.emit(conf.tlog, internal.DCTL0004, func(e *zerolog.Event) *zerolog.Event {
					return e.Err(err)
				})
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, logoURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	func() {
		err := resp.Body.Close()
		if err != nil {
			conf.tlog.Warn().Err(err).Msg("could not close http body")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status %d", resp.StatusCode)
	}
	return nil
}

func (conf *Conf) writeBack(out bytes.Buffer) exitvals.CheckSeverity {
	// Create temporary file
	outfile, err := os.CreateTemp("./", path.Base(conf.fileName))
	if err != nil {
		conf.emit(conf.tlog, internal.DCTL0005, func(e *zerolog.Event) *zerolog.Event {
			return e.Err(err)
		})
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
		conf.emit(conf.tlog, internal.DCTL0004, func(e *zerolog.Event) *zerolog.Event {
			return e.Err(err)
		})
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
		conf.emit(conf.tlog, internal.DCTL0006, func(e *zerolog.Event) *zerolog.Event {
			return e.Err(err)
		})
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
			conf.emit(conf.tlog, internal.DCTL1026, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("domain", srdList[i])
			})
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
		exitVal |= conf.emit(conf.tlog, internal.DCTL5000, nil)
	}
	if template.SyncPubKeyDomain == "" {
		exitVal |= conf.emit(conf.tlog, internal.DCTL5001, nil)
	}
	if template.SharedServiceName {
		exitVal |= conf.emit(conf.tlog, internal.DCTL5002, nil)
	}
	if template.SyncRedirectDomain != "" {
		exitVal |= conf.emit(conf.tlog, internal.DCTL5003, nil)
	}
	if template.MultiInstance {
		exitVal |= conf.emit(conf.tlog, internal.DCTL5004, nil)
	}
	if template.WarnPhishing {
		exitVal |= conf.emit(conf.tlog, internal.DCTL5005, nil)
	}
	if template.HostRequired {
		exitVal |= conf.emit(conf.tlog, internal.DCTL5006, nil)
	}
	return exitVal
}
