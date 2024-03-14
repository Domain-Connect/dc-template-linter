package libdctlint

import (
	"reflect"
	"strings"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"

	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"
)

const strCNAME = "CNAME"

func (conf *Conf) checkRecord(
	template internal.Template,
	rnum int,
	record internal.Record,
	conflictingTypes map[string]string,
) exitvals.CheckSeverity {
	// A record specific init
	exitVal := exitvals.CheckOK
	rlog := conf.tlog.With().Str("groupid", record.GroupID).Int("record", rnum).Logger()
	rlog.Debug().Str("type", record.Type).Str("host", record.Host).Msg("check record")

	// Try to catch CNAME usage with other records
	if t, ok := conflictingTypes[record.GroupID+"/"+record.Host]; ok && (t == strCNAME || record.Type == strCNAME) {
		rlog.Error().
			Str("host", record.Host).
			Str("type", record.Type).
			Str("othertype", t).
			Msg("CNAME cannot be mixed with other record types")
		exitVal |= exitvals.CheckError
	}
	conflictingTypes[record.GroupID+"/"+record.Host] = record.Type

	// The type specific checks are mostly from the Domain Connect spec
	switch record.Type {
	case strCNAME, "NS":
		if record.Host == "@" {
			if conf.cloudflare {
				rlog.Info().Str("type", record.Type).Msg("domains must use Cloudflares CNAME flattening setting")
				exitVal |= exitvals.CheckInfo
			} else if !template.HostRequired {
				rlog.Error().Str("type", record.Type).Msg("record host must not be @ when template hostRequired is false")
				exitVal |= exitvals.CheckError
			}
		}
		fallthrough
	case "A", "AAAA":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= exitvals.CheckError
		}
		exitVal |= targetCheck(record, "pointsTo", rlog)

	case "TXT":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= exitvals.CheckError
		}
		exitVal |= targetCheck(record, "data", rlog)
		if conf.cloudflare {
			if record.TxtCMM != "" || record.TxtCMM == "None" {
				rlog.Info().Msg("Cloudflare does not support txtConflictMatchingMode record settings")
				exitVal |= exitvals.CheckInfo
			}
			if record.TxtCMP != "" {
				rlog.Info().Msg("Cloudflare does not support txtConflictMatchingPrefix record settings")
				exitVal |= exitvals.CheckInfo
			}
		} else if record.TxtCMM == "Prefix" && record.TxtCMP == "" {
			rlog.Warn().Str("type", record.Type).Msg("record txtConflictMatchingPrefix is not defined")
			exitVal |= exitvals.CheckWarn
		}

	case "MX":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= exitvals.CheckError
		}
		exitVal |= targetCheck(record, "pointsTo", rlog)
		if record.Priority < 0 || max31b < record.Priority {
			rlog.Error().Str("type", record.Type).Int("priority", int(record.Priority)).Msg("invalid priority")
			exitVal |= exitvals.CheckError
		}

	case "SRV":
		exitVal |= targetCheck(record, "target", rlog)
		if isInvalidProtocol(record.Protocol) {
			rlog.Warn().Str("type", record.Type).Str("protocol", record.Protocol).Msg("invalid protocol")
			exitVal |= exitvals.CheckWarn
		}
		if record.Priority < 0 || max31b < record.Priority {
			rlog.Error().Str("type", record.Type).Int("priority", int(record.Priority)).Msg("invalid priority")
			exitVal |= exitvals.CheckError
		}
		if record.Service == "" {
			rlog.Error().Str("type", record.Type).Msg("record service must not be empty")
			exitVal |= exitvals.CheckError
		}
		if record.Weight < 0 || max31b < record.Weight {
			rlog.Error().Str("type", record.Type).Int("weight", int(record.Weight)).Msg("invalid weight")
			exitVal |= exitvals.CheckError
		}
		if record.Port < 1 || max16b < record.Port {
			rlog.Error().Str("type", record.Type).Int("port", int(record.Port)).Msg("invalid port")
			exitVal |= exitvals.CheckError
		}

	case "SPFM":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= exitvals.CheckError
		}
		if record.SPFRules == "" {
			rlog.Error().Str("type", record.Type).Msg("record spfRules must not be empty")
			exitVal |= exitvals.CheckError
		}
		if strings.HasPrefix(record.SPFRules, "v=spf1") {
			rlog.Error().Str("type", record.Type).Msg("spfRules must not include v=spf1")
			exitVal |= exitvals.CheckError
		}
		if strings.HasSuffix(record.SPFRules, "all") {
			rlog.Error().Str("type", record.Type).Msg("spfRules must not include trailing all rule")
			exitVal |= exitvals.CheckError
		}

	case "APEXCNAME":
		if conf.cloudflare {
			rlog.Info().Msg("Cloudflare does not support APEXCNAME, use CNAME instead")
			exitVal |= exitvals.CheckInfo
		}

	case "REDIR301", "REDIR302":
		if record.Target == "" {
			rlog.Error().Str("type", record.Type).Msg("record target must not be empty")
			exitVal |= exitvals.CheckError
		}
	default:
		rlog.Info().Str("type", record.Type).Msg("unusual record type check DNS providers if they support it")
		exitVal |= exitvals.CheckInfo
	}

	// Check use of underscore host names.
	exitVal |= conf.checkUnderscoreNames(record.Type, record.Host)

	// The spec does not tell type cannot be variable, but if/when it is
	// reasoning about effects of applying a template becomes quite hard
	// if not impossible. Without dubt a variable type will cascade need
	// to use variable in all other parameters, and that means service
	// provider will basically grant oneself 100% full access to clients
	// DNS content. Domain Connect is expected to be powerful, but that
	// is too much power.
	if isVariable(record.Type) {
		rlog.Error().Msg("record type must not be variable")
		exitVal |= exitvals.CheckError
	}

	// A calid json int can be out of bounds in DNS
	if record.TTL < 0 || max31b < record.TTL {
		rlog.Error().Str("type", record.Type).Int("ttl", int(record.TTL)).Msg("invalid TTL")
		exitVal |= exitvals.CheckError
	} else if conf.cloudflare && record.TTL == 0 {
		rlog.Info().Str("type", record.Type).Int("ttl", 0).Msg("Cloudflare will replace zero ttl with value of 300")
		exitVal |= exitvals.CheckInfo
	}

	// Enforce Domain Connect spec
	if isVariable(record.GroupID) {
		rlog.Error().Msg("record groupId must not be variable")
		exitVal |= exitvals.CheckError
	}
	if isVariable(record.TxtCMP) {
		rlog.Error().Msg("record txtConflictMatchingPrefix must not be variable")
		exitVal |= exitvals.CheckError
	}

	// DNS provider specific checks
	if conf.cloudflare {
		if record.Essential != "" {
			rlog.Info().Msg("Cloudflare does not support essential record settings")
			exitVal |= exitvals.CheckInfo
		}
	}

	exitVal |= findInvalidTemplateStrings(record, rlog)

	return exitVal
}

func isInvalidProtocol(proto string) bool {
	// in SRV record
	switch strings.ToLower(proto) {
	case "_tcp", "_udp", "_tls":
		return false
	}
	return true
}

var mutuallyExclusive = []string{
	"data",
	"name",
	"pointsTo",
	"target",
}

func targetCheck(record internal.Record, requiredField string, rlog zerolog.Logger) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK

	recordTypes := reflect.TypeOf(record)

	for i := 0; i < recordTypes.NumField(); i++ {
		field := recordTypes.Field(i)

		jsonTag, ok := field.Tag.Lookup("json")
		if ok {
			csv := strings.Split(jsonTag, ",")
			if csv[0] == "" {
				rlog.Error().Str("type", record.Type).Msg("json tag not defined")
				exitVal |= exitvals.CheckError
				continue
			}
			if csv[0] == requiredField {
				if reflect.ValueOf(record).FieldByName(field.Name).String() == "" {
					rlog.Error().Str("field", requiredField).Str("type", record.Type).Msg("required field is missing")
					exitVal |= exitvals.CheckError
				}
				continue
			}
			if record.Type == "SRV" && csv[0] == "name" {
				continue
			}
			if slices.Contains(mutuallyExclusive, csv[0]) {
				if reflect.ValueOf(record).FieldByName(field.Name).String() != "" {
					rlog.Info().Str("field", csv[0]).Str("type", record.Type).Msg("unnecessary field found")
					exitVal |= exitvals.CheckInfo
				}
			}
		}
	}

	return exitVal
}
