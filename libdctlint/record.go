package libdctlint

import (
	"strings"

	"github.com/Domain-Connect/dc-template-linter/internal"
)

const strCNAME = "CNAME"

func (conf *Conf) checkRecord(
	template internal.Template,
	rnum int,
	record internal.Record,
	conflictingTypes map[string]string,
) internal.CheckSeverity {
	// A record specific init
	exitVal := internal.CheckOK
	rlog := conf.tlog.With().Str("groupid", record.GroupID).Int("record", rnum).Logger()
	rlog.Debug().Str("type", record.Type).Str("host", record.Host).Msg("check record")

	// Try to catch CNAME usage with other records
	if t, ok := conflictingTypes[record.GroupID+"/"+record.Host]; ok && (t == strCNAME || record.Type == strCNAME) {
		rlog.Error().
			Str("host", record.Host).
			Str("type", record.Type).
			Str("othertype", t).
			Msg("CNAME cannot be mixed with other record types")
		exitVal |= internal.CheckError
	}
	conflictingTypes[record.GroupID+"/"+record.Host] = record.Type

	// The type specific checks are mostly from the Domain Connect spec
	switch record.Type {
	case strCNAME, "NS":
		if record.Host == "@" {
			if conf.cloudflare {
				rlog.Info().Str("type", record.Type).Msg("domains must use Cloudflares CNAME flattening setting")
				exitVal |= internal.CheckInfo
			} else if !template.HostRequired {
				rlog.Error().Str("type", record.Type).Msg("record host must not be @ when template hostRequired is false")
				exitVal |= internal.CheckError
			}
		}
		fallthrough
	case "A", "AAAA":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= internal.CheckError
		}
		if record.PointsTo == "" {
			rlog.Error().Str("type", record.Type).Msg("record pointsTo must not be empty")
			exitVal |= internal.CheckError
		}

	case "TXT":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= internal.CheckError
		}
		if record.Data == "" {
			rlog.Error().Str("type", record.Type).Msg("record data must not be empty")
			exitVal |= internal.CheckError
		}
		if conf.cloudflare {
			if record.TxtCMM != "" || record.TxtCMM == "None" {
				rlog.Info().Msg("Cloudflare does not support txtConflictMatchingMode record settings")
				exitVal |= internal.CheckInfo
			}
			if record.TxtCMP != "" {
				rlog.Info().Msg("Cloudflare does not support txtConflictMatchingPrefix record settings")
				exitVal |= internal.CheckInfo
			}
		} else if record.TxtCMM == "Prefix" && record.TxtCMP == "" {
			rlog.Warn().Str("type", record.Type).Msg("record txtConflictMatchingPrefix is not defined")
			exitVal |= internal.CheckWarn
		}

	case "MX":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= internal.CheckError
		}
		if record.PointsTo == "" {
			rlog.Error().Str("type", record.Type).Msg("record pointsTo must not be empty")
			exitVal |= internal.CheckError
		}
		if record.Priority < 0 || max31b < record.Priority {
			rlog.Error().Str("type", record.Type).Int("priority", int(record.Priority)).Msg("invalid priority")
			exitVal |= internal.CheckError
		}

	case "SRV":
		if record.Target == "" {
			rlog.Error().Str("type", record.Type).Msg("record target must not be empty")
			exitVal |= internal.CheckError
		}
		if isInvalidProtocol(record.Protocol) {
			rlog.Warn().Str("type", record.Type).Str("protocol", record.Protocol).Msg("invalid protocol")
			exitVal |= internal.CheckWarn
		}
		if record.Priority < 0 || max31b < record.Priority {
			rlog.Error().Str("type", record.Type).Int("priority", int(record.Priority)).Msg("invalid priority")
			exitVal |= internal.CheckError
		}
		if record.Service == "" {
			rlog.Error().Str("type", record.Type).Msg("record service must not be empty")
			exitVal |= internal.CheckError
		}
		if record.Weight < 0 || max31b < record.Weight {
			rlog.Error().Str("type", record.Type).Int("weight", int(record.Weight)).Msg("invalid weight")
			exitVal |= internal.CheckError
		}
		if record.Port < 1 || max16b < record.Port {
			rlog.Error().Str("type", record.Type).Int("port", int(record.Port)).Msg("invalid port")
			exitVal |= internal.CheckError
		}

	case "SPFM":
		if record.Host == "" {
			rlog.Error().Str("type", record.Type).Msg("record host must not be empty")
			exitVal |= internal.CheckError
		}
		if record.SPFRules == "" {
			rlog.Error().Str("type", record.Type).Msg("record spfRules must not be empty")
			exitVal |= internal.CheckError
		}

	case "APEXCNAME":
		if conf.cloudflare {
			rlog.Info().Msg("Cloudflare does not support APEXCNAME, use CNAME instead")
			exitVal |= internal.CheckInfo
		}

	case "REDIR301", "REDIR302":
		if record.Target == "" {
			rlog.Error().Str("type", record.Type).Msg("record target must not be empty")
			exitVal |= internal.CheckError
		}
	default:
		rlog.Info().Str("type", record.Type).Msg("unusual record type check DNS providers if they support it")
		exitVal |= internal.CheckInfo
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
		exitVal |= internal.CheckError
	}

	// A calid json int can be out of bounds in DNS
	if record.TTL < 0 || max31b < record.TTL {
		rlog.Error().Str("type", record.Type).Int("ttl", int(record.TTL)).Msg("invalid TTL")
		exitVal |= internal.CheckError
	} else if conf.cloudflare && record.TTL == 0 {
		rlog.Info().Str("type", record.Type).Int("ttl", 0).Msg("Cloudflare will replace zero ttl with value of 300")
		exitVal |= internal.CheckInfo
	}

	// Enforce Domain Connect spec
	if isVariable(record.GroupID) {
		rlog.Error().Msg("record groupId must not be variable")
		exitVal |= internal.CheckError
	}
	if isVariable(record.TxtCMP) {
		rlog.Error().Msg("record txtConflictMatchingPrefix must not be variable")
		exitVal |= internal.CheckError
	}

	// DNS provider specific checks
	if conf.cloudflare {
		if record.Essential != "" {
			rlog.Info().Msg("Cloudflare does not support essential record settings")
			exitVal |= internal.CheckInfo
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
