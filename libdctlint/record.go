package libdctlint

import (
	"reflect"
	"regexp"
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
	rlog := conf.tlog.With().Str("groupid", record.GroupID).Int("record", rnum).Str("type", record.Type).Logger()
	rlog.Debug().Str("host", record.Host).Msg("check record")

	// Try to catch CNAME usage with other records
	if t, ok := conflictingTypes[record.GroupID+"/"+record.Host]; ok && (t == strCNAME || record.Type == strCNAME) {
		rlog.Error().
			Str("host", record.Host).
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
				rlog.Info().Msg("domains must use Cloudflares CNAME flattening setting")
				exitVal |= exitvals.CheckInfo
			} else if !template.HostRequired {
				rlog.Error().Msg("record host must not be @ when template hostRequired is false")
				exitVal |= exitvals.CheckError
			}
		}
		fallthrough
	case "A", "AAAA":
		if record.Host == "" {
			rlog.Error().Msg("record host must not be empty")
			exitVal |= exitvals.CheckError
		}
		exitVal |= targetCheck(record, "pointsTo", rlog)

	case "TXT":
		if record.Host == "" {
			rlog.Error().Msg("record host must not be empty")
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
			rlog.Warn().Msg("record txtConflictMatchingPrefix is not defined")
			exitVal |= exitvals.CheckWarn
		}

	case "MX":
		if record.Host == "" {
			rlog.Error().Msg("record host must not be empty")
			exitVal |= exitvals.CheckError
		}
		exitVal |= targetCheck(record, "pointsTo", rlog)
		if record.Priority < 0 || max31b < record.Priority {
			rlog.Error().Int("priority", int(record.Priority)).Msg("invalid priority")
			exitVal |= exitvals.CheckError
		}

	case "SRV":
		exitVal |= targetCheck(record, "target", rlog)
		if isInvalidProtocol(record.Protocol) {
			rlog.Warn().Str("protocol", record.Protocol).Msg("invalid protocol")
			exitVal |= exitvals.CheckWarn
		}
		if record.Priority < 0 || max31b < record.Priority {
			rlog.Error().Int("priority", int(record.Priority)).Msg("invalid priority")
			exitVal |= exitvals.CheckError
		}
		if record.Service == "" {
			rlog.Error().Msg("record service must not be empty")
			exitVal |= exitvals.CheckError
		}
		if record.Weight < 0 || max31b < record.Weight {
			rlog.Error().Int("weight", int(record.Weight)).Msg("invalid weight")
			exitVal |= exitvals.CheckError
		}
		if record.Port < 1 || max16b < record.Port {
			rlog.Error().Int("port", int(record.Port)).Msg("invalid port")
			exitVal |= exitvals.CheckError
		}

	case "SPFM":
		if record.Host == "" {
			rlog.Error().Msg("record host must not be empty")
			exitVal |= exitvals.CheckError
		}
		exitVal |= checkSPFRules(strings.ToLower(record.SPFRules), rlog)

	case "APEXCNAME":
		if conf.cloudflare {
			rlog.Info().Msg("Cloudflare does not support APEXCNAME, use CNAME instead")
			exitVal |= exitvals.CheckInfo
		}

	case "REDIR301", "REDIR302":
		if record.Target == "" {
			rlog.Error().Msg("record target must not be empty")
			exitVal |= exitvals.CheckError
		}
	default:
		rlog.Info().Msg("unusual record type check DNS providers if they support it")
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
		rlog.Error().Int("ttl", int(record.TTL)).Msg("invalid TTL")
		exitVal |= exitvals.CheckError
	} else if conf.cloudflare && record.TTL == 0 {
		rlog.Info().Int("ttl", 0).Msg("Cloudflare will replace zero ttl with value of 300")
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
				rlog.Error().Msg("json tag not defined")
				exitVal |= exitvals.CheckError
				continue
			}
			if csv[0] == requiredField {
				if reflect.ValueOf(record).FieldByName(field.Name).String() == "" {
					rlog.Error().Str("field", requiredField).Msg("required field is missing")
					exitVal |= exitvals.CheckError
				}
				continue
			}
			if record.Type == "SRV" && csv[0] == "name" {
				continue
			}
			if slices.Contains(mutuallyExclusive, csv[0]) {
				if reflect.ValueOf(record).FieldByName(field.Name).String() != "" {
					rlog.Info().Str("field", csv[0]).Msg("unnecessary field found")
					exitVal |= exitvals.CheckInfo
				}
			}
		}
	}

	return exitVal
}

type spfTrack struct {
	exp      bool
	redirect bool
}

var modifierRe = regexp.MustCompile(`^((?i)[a-z][a-z0-9_.-]*)=(.*)`)

func checkSPFRules(rules string, rlog zerolog.Logger) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK

	if rules == "" {
		rlog.Error().Msg("record spfRules must not be empty")
		return exitvals.CheckError
	}
	if strings.HasPrefix(rules, "v=spf1") {
		rlog.Error().Msg("spfRules must not include v=spf1")
		exitVal |= exitvals.CheckError
	}
	if strings.HasSuffix(rules, "all") {
		rlog.Error().Msg("spfRules must not include trailing all rule")
		exitVal |= exitvals.CheckError
	}

	fields := strings.Fields(rules)
	track := spfTrack{}

	for _, field := range fields {
		if isVariable(field) {
			// variables are ok
			continue
		}

		matches := modifierRe.FindStringSubmatch(field)
		if matches != nil {
			switch matches[1] {
			case "redirect":
				if track.redirect {
					rlog.Error().Msg("spfRules has multiple redirect fields")
					exitVal |= exitvals.CheckError
				}
				track.redirect = true
			case "exp":
				if track.exp {
					rlog.Error().Msg("spfRules has multiple exp fields")
					exitVal |= exitvals.CheckError
				}
				track.exp = true
			default:
				rlog.Error().Str("field", matches[1]).Msg("spfRules contains unknown macro field")
				exitVal |= exitvals.CheckError
			}
			continue
		}

		switch field[0] {
		case '+':
			field = field[1:]
		case '-':
			field = field[1:]
		case '~':
			field = field[1:]
		case '?':
			field = field[1:]
		}

		separator := strings.IndexAny(field, ":")
		if -1 < separator {
			field = field[:separator]
		}

		switch field {
		case "include", "a", "mx", "ptr", "ip4", "ip6", "exists":
			// these are ok
		default:
			rlog.Error().Str("modifier", field).Msg("spfRules contains unknown modifier")
			exitVal |= exitvals.CheckError
		}
	}

	return exitVal
}
