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
	"strings"

	"github.com/Domain-Connect/dc-template-linter/libdctlint/internal"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	max16b = 1<<16 - 1
	max31b = 1<<31 - 1
)

// A CheckSeverity represent status of the template check.
type CheckSeverity uint32

const (
	CheckOK    CheckSeverity = 0
	CheckWarn  CheckSeverity = 1 << 0
	CheckError CheckSeverity = 1 << 1
	CheckFatal CheckSeverity = 1 << 2
)

// LibdctlintConf holds template checking instructions. The field type
// FileName must be updated each time CheckTemplate() is called to match
// with the bufio.Reader argument.
type LibdctlintConf struct {
	FileName    string
	tlog        zerolog.Logger
	collision   map[string]bool
	checkLogos  bool
	cloudflare  bool
	inplace     bool
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
func NewConf(checkLogos, cloudflare, inplace, prettyPrint bool) LibdctlintConf {
	return LibdctlintConf{
		collision:   make(map[string]bool),
		checkLogos:  checkLogos,
		cloudflare:  cloudflare,
		inplace:     inplace,
		prettyPrint: prettyPrint,
	}
}

// CheckTemplate takes bufio.Reader as an argument and will run template
// checks according to the LibdctlintConf configuration. Please remember to
// set conf.FileName appropriately before calling this function to avoid
// confusing results.
func (conf *LibdctlintConf) CheckTemplate(f *bufio.Reader) CheckSeverity {
	exitVal := CheckOK
	conf.tlog = log.With().Str("template", conf.FileName).Logger()
	internal.Log = conf.tlog

	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()

	var template internal.Template
	err := decoder.Decode(&template)
	if err != nil {
		conf.tlog.Error().Err(err).Msg("json decode error")
		return CheckFatal
	}
	if internal.ExitVal != 0 {
		exitVal |= CheckSeverity(internal.ExitVal)
	}

	if checkInvalidChars(template.ProviderID) {
		conf.tlog.Error().Str("providerId", template.ProviderID).Msg("providerId contains invalid characters")
		exitVal |= CheckError
	}

	if checkInvalidChars(template.ServiceID) {
		conf.tlog.Error().Str("serviceId", template.ServiceID).Msg("serviceId contains invalid characters")
		exitVal |= CheckError
	}

	if _, found := conf.collision[template.ProviderID+"/"+template.ServiceID]; found {
		conf.tlog.Error().Str("providerId", template.ProviderID).Str("serviceId", template.ServiceID).Msg("duplicate provierId + serviceId detected")
		exitVal |= CheckError
	}
	conf.collision[template.ProviderID+"/"+template.ServiceID] = true

	Validator := validator.New()
	err = Validator.Struct(template)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			conf.tlog.Warn().Err(err).Msg("template field validation")
			exitVal |= CheckWarn
		}
	}

	if template.Version < 0 {
		conf.tlog.Info().Msg("use of negative version number is not recommended")
	}

	if template.Shared && !template.SharedProviderName {
		conf.tlog.Info().Msg("shared flag is deprecated, use sharedProviderName as well")
		// Override to ensure settings in pretty-print output are correct
		template.Shared = true
		template.SharedProviderName = true
	}
	if !template.Shared && template.SharedProviderName {
		conf.tlog.Info().Msg("sharedProviderName is in use, but shared backward compatability is not set")
		// Override to ensure settings in pretty-print output are correct
		template.Shared = true
		template.SharedProviderName = true
	}

	if err := conf.isUnreachable(template.Logo); err != nil {
		conf.tlog.Warn().Err(err).Str("logoUrl", template.Logo).Msg("logo check failed")
	}

	if conf.cloudflare {
		exitVal |= conf.cloudflareTemplateChecks(template)
	}

	conflictingTypes := make(map[string]string)
	for rnum, record := range template.Records {
		exitVal |= conf.checkRecord(template, rnum, record, conflictingTypes)
	}

	if conf.prettyPrint || conf.inplace {
		pp, err := json.Marshal(template)
		if err != nil {
			conf.tlog.Error().Err(err).Msg("json marshaling failed")
			return CheckError
		}
		var out bytes.Buffer
		err = json.Indent(&out, pp, "", "    ")
		if err != nil {
			conf.tlog.Error().Err(err).Msg("json indenting failed")
			return CheckError
		}
		fmt.Fprintf(&out, "\n")
		if conf.inplace {
			exitVal |= conf.writeBack(out)
		} else {
			_, err = out.WriteTo(os.Stdout)
			if err != nil {
				conf.tlog.Error().Err(err).Msg("write failed")
				exitVal |= CheckError
			}
		}
	}
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

func (conf *LibdctlintConf) isUnreachable(logoUrl string) error {
	if !conf.checkLogos || logoUrl == "" {
		return nil
	}
	resp, err := http.Get(logoUrl)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status %d", resp.StatusCode)
	}
	return nil
}

func (conf *LibdctlintConf) writeBack(out bytes.Buffer) CheckSeverity {
	f, err := os.CreateTemp("./", path.Base(conf.FileName))
	if err != nil {
		conf.tlog.Warn().Err(err).Msg("could not create temporary file")
		return CheckError
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	_, err = out.WriteTo(w)
	if err != nil {
		conf.tlog.Warn().Err(err).Msg("could write to temporary file")
		return CheckError
	}
	w.Flush()
	err = os.Rename(f.Name(), conf.FileName)
	if err != nil {
		conf.tlog.Warn().Err(err).Msg("could not move template back inplace")
		return CheckWarn
	}
	conf.tlog.Debug().Str("tmpfile", f.Name()).Msg("updated")
	return CheckOK
}

const strCNAME = "CNAME"

func (conf *LibdctlintConf) checkRecord(
	template internal.Template,
	rnum int,
	record internal.Record,
	conflictingTypes map[string]string,
) CheckSeverity {
	exitVal := CheckOK
	rlog := conf.tlog.With().Int("record", rnum).Logger()
	rlog.Debug().Str("type", record.Type).Str("groupid", record.GroupID).Str("host", record.Host).Msg("check record")

	if t, ok := conflictingTypes[record.GroupID+"/"+record.Host]; ok && (t == strCNAME || record.Type == strCNAME) {
		rlog.Error().
			Str("groupid", record.GroupID).
			Str("host", record.Host).
			Str("type", record.Type).
			Str("othertype", t).
			Msg("CNAME cannot be mixed with other record types")
		exitVal |= CheckError
	}
	conflictingTypes[record.GroupID+"/"+record.Host] = record.Type

	switch record.Type {
	case strCNAME, "NS":
		if record.Host == "@" {
			if conf.cloudflare {
				rlog.Info().Str("type", record.Type).Msg("domains must use Cloudflares CNAME flattening setting")
				exitVal |= CheckWarn
			} else if !template.HostRequired {
				rlog.Error().Str("type", record.Type).Msg("record host must not be @ when template hostRequired is false")
				exitVal |= CheckError
			}
		}
		fallthrough
	case "A", "AAAA":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= CheckError
		}

	case "TXT":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= CheckError
		}
		if record.Data == "" {
			rlog.Error().Str("type", record.Type).Msg("record data must not be empty")
			exitVal |= CheckError
		}
		if conf.cloudflare {
			if record.TxtCMM != "" || record.TxtCMM == "None" {
				rlog.Info().Msg("Cloudflare does not support txtConflictMatchingMode record settings")
			}
			if record.TxtCMP != "" {
				rlog.Info().Msg("Cloudflare does not support txtConflictMatchingPrefix record settings")
			}
		} else {
			if record.TxtCMM == "Prefix" && record.TxtCMP == "" {
				rlog.Warn().Str("type", record.Type).Msg("record txtConflictMatchingPrefix is not defined")
				exitVal |= CheckWarn
			}
		}

	case "MX":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= CheckError
		}
		if record.PointsTo == "" {
			rlog.Error().Str("type", record.Type).Msg("record pointsTo must not be empty")
			exitVal |= CheckError
		}
		if record.Priority < 0 || max31b < record.Priority {
			rlog.Error().Str("type", record.Type).Int("priority", int(record.Priority)).Msg("invalid priority")
			exitVal |= CheckError
		}

	case "SRV":
		if record.Name == "" {
			rlog.Error().Str("type", record.Type).Msg("record name must not be empty")
			exitVal |= CheckError
		}
		if record.Target == "" {
			rlog.Error().Str("type", record.Type).Msg("record target must not be empty")
			exitVal |= CheckError
		}
		if isInvalidProtocol(record.Protocol) {
			rlog.Warn().Str("type", record.Type).Str("protocol", record.Protocol).Msg("invalid protocol")
			exitVal |= CheckWarn
		}
		if record.Priority < 0 || max31b < record.Priority {
			rlog.Error().Str("type", record.Type).Int("priority", int(record.Priority)).Msg("invalid priority")
			exitVal |= CheckError
		}
		if record.Service == "" {
			rlog.Error().Str("type", record.Type).Msg("record service must not be empty")
			exitVal |= CheckError
		}
		if record.Weight < 0 || max31b < record.Weight {
			rlog.Error().Str("type", record.Type).Int("weigth", int(record.Weight)).Msg("invalid weigth")
			exitVal |= CheckError
		}
		if record.Port < 1 || max16b < record.Port {
			rlog.Error().Str("type", record.Type).Int("port", int(record.Port)).Msg("invalid port")
			exitVal |= CheckError
		}

	case "SPFM":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= CheckError
		}
		if record.SPFRules == "" {
			rlog.Error().Str("type", record.Type).Msg("record spfRules must not be empty")
			exitVal |= CheckError
		}

	case "APEXCNAME":
		if conf.cloudflare {
			rlog.Info().Msg("Cloudflare does not support APEXCNAME, use CNAME instead")
		}

	case "REDIR301", "REDIR302":
		if record.Target == "" {
			rlog.Error().Str("type", record.Type).Msg("record target must not be empty")
			exitVal |= CheckError
		}
	default:
		rlog.Info().Str("type", record.Type).Msg("unusual record type check DNS providers if they support it")
	}

	if isVariable(record.Type) {
		rlog.Error().Msg("record type must not be variable")
		exitVal |= CheckError
	}

	if record.TTL < 0 || max31b < record.TTL {
		rlog.Error().Str("type", record.Type).Int("ttl", int(record.TTL)).Msg("invalid TTL")
		exitVal |= CheckError
	} else if conf.cloudflare && record.TTL == 0 {
		rlog.Info().Str("type", record.Type).Int("ttl", 0).Msg("Cloudflare will replace zero ttl with value of 300")
	}

	if isVariable(record.GroupID) {
		rlog.Error().Msg("record groupId must not be variable")
		exitVal |= CheckError
	}

	if isVariable(record.TxtCMP) {
		rlog.Error().Msg("record txtConflictMatchingPrefix must not be variable")
		exitVal |= CheckError
	}

	if conf.cloudflare {
		if record.Essential != "" {
			rlog.Info().Msg("Cloudflare does not support essential record settings")
		}
	}
	return exitVal
}

func isInvalidProtocol(proto string) bool {
	switch strings.ToLower(proto) {
	case "_tcp", "_udp", "_tls":
		return false
	}
	return true
}

func isVariable(s string) bool {
	return strings.Count(s, "%") > 1
}

func (conf *LibdctlintConf) cloudflareTemplateChecks(template internal.Template) CheckSeverity {
	exitVal := CheckOK
	if template.SyncBlock {
		conf.tlog.Error().Msg("Cloudflare does not support syncBlock")
		exitVal |= CheckError
	}
	if template.SyncPubKeyDomain == "" {
		conf.tlog.Error().Msg("Cloudflare requires syncPubKeyDomain")
		exitVal |= CheckError
	}
	if template.SharedServiceName {
		conf.tlog.Info().Msg("Cloudflare does not support sharedServiceName")
		exitVal |= CheckWarn
	}
	if template.SyncRedirectDomain != "" {
		conf.tlog.Info().Msg("Cloudflare does not support syncRedirectDomain")
		exitVal |= CheckWarn
	}
	if template.MultiInstance {
		conf.tlog.Info().Msg("Cloudflare does not support multiInstance")
		exitVal |= CheckWarn
	}
	if template.WarnPhishing {
		conf.tlog.Info().Msg("Cloudflare does not use warnPhishing because syncPubKeyDomain is required")
		exitVal |= CheckWarn
	}
	if template.HostRequired {
		conf.tlog.Info().Msg("Cloudflare does not support hostRequired")
		exitVal |= CheckWarn
	}
	return exitVal
}
