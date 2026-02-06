package libdctlint

import (
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"

	"github.com/rs/zerolog"
)

const strCNAME = "CNAME"
const MaxTTL = (1 << 31) - 1 // 2147483647

func (conf *Conf) checkRecord(
	template internal.Template,
	rnum int,
	record *internal.Record,
	conflictingTypes map[string]string,
) exitvals.CheckSeverity {
	// A record specific init
	exitVal := exitvals.CheckOK
	rlog := conf.tlog.With().Str("groupid", record.GroupID).Int("record", rnum).Str("type", record.Type).Logger()
	rlog.Debug().Str("host", record.Host).Msg("check record")

	exitVal |= conf.findDuplicates(record, rlog)

	// Try to catch CNAME usage with other records
	if t, ok := conflictingTypes[record.GroupID+"/"+record.Host]; ok && (t == strCNAME || record.Type == strCNAME) {
		rlog.Error().
			Str("host", record.Host).
			Str("othertype", t).
			EmbedObject(internal.DCTL1011).Msg("")
		exitVal |= exitvals.CheckError
	}
	conflictingTypes[record.GroupID+"/"+record.Host] = record.Type

	// The type specific checks are mostly from the Domain Connect spec
	switch record.Type {
	case strCNAME, "NS":
		if record.Host == "@" {
			if conf.cloudflare {
				rlog.Info().EmbedObject(internal.DCTL5007).Msg("")
				exitVal |= exitvals.CheckInfo
			} else if !template.HostRequired {
				rlog.Error().EmbedObject(internal.DCTL1012).Msg("")
				exitVal |= exitvals.CheckError
			}
		}
		fallthrough
	case "A", "AAAA":
		if record.Host == "" {
			rlog.Error().Str("key", "host").EmbedObject(internal.DCTL1013).Msg("")
			exitVal |= exitvals.CheckError
		}
		exitVal |= targetCheck(record, "pointsTo", rlog)

	case "TXT":
		if record.Host == "" {
			rlog.Error().Str("key", "host").EmbedObject(internal.DCTL1013).Msg("")
			exitVal |= exitvals.CheckError
		}
		exitVal |= targetCheck(record, "data", rlog)
		if conf.cloudflare {
			if record.TxtCMM != "" || record.TxtCMM == "None" {
				rlog.Info().Str("key", "txtConflictMatchingMode").EmbedObject(internal.DCTL5008).Msg("")
				exitVal |= exitvals.CheckInfo
			}
			if record.TxtCMP != "" {
				rlog.Info().Str("key", "txtConflictMatchingPrefix").EmbedObject(internal.DCTL5008).Msg("")
				exitVal |= exitvals.CheckInfo
			}
		} else if record.TxtCMM == "Prefix" && record.TxtCMP == "" {
			rlog.Warn().Str("key", "txtConflictMatchingPrefix").EmbedObject(internal.DCTL1013).Msg("")
			exitVal |= exitvals.CheckWarn
		}
		if strings.Contains(record.Data, "v=spf1") {
			rlog.Info().EmbedObject(internal.DCTL1014).Msg("")
			exitVal |= exitvals.CheckInfo
		}

	case "MX":
		if record.Host == "" {
			rlog.Error().Str("key", "host").EmbedObject(internal.DCTL1013).Msg("")
			exitVal |= exitvals.CheckError
		}
		exitVal |= targetCheck(record, "pointsTo", rlog)
		if priority, ok := record.Priority.Uint32(); !ok || max31b < priority {
			rlog.Error().Uint32("priority", priority).EmbedObject(internal.DCTL1015).Msg("")
			exitVal |= exitvals.CheckError
		}

	case "SRV":
		exitVal |= targetCheck(record, "target", rlog)
		if isInvalidProtocol(record.Protocol) {
			rlog.Warn().Str("protocol", record.Protocol).EmbedObject(internal.DCTL1015).Msg("")
			exitVal |= exitvals.CheckWarn
		}
		if priority, ok := record.Priority.Uint32(); !ok || max31b < priority {
			rlog.Error().Uint32("priority", priority).EmbedObject(internal.DCTL1015).Msg("")
			exitVal |= exitvals.CheckError
		}
		if record.Service == "" {
			rlog.Error().Str("key", "service").EmbedObject(internal.DCTL1013).Msg("")
			exitVal |= exitvals.CheckError
		}
		if weight, ok := record.Weight.Uint32(); !ok || max31b < weight {
			rlog.Error().Uint32("weight", weight).EmbedObject(internal.DCTL1015).Msg("")
			exitVal |= exitvals.CheckError
		}
		if port, ok := record.Port.Uint16(); !ok || max16b < port {
			rlog.Error().Uint16("port", port).EmbedObject(internal.DCTL1015).Msg("")
			exitVal |= exitvals.CheckError
		}

	case "SPFM":
		if record.Host == "" {
			rlog.Error().Str("key", "host").EmbedObject(internal.DCTL1013).Msg("")
			exitVal |= exitvals.CheckError
		}
		exitVal |= checkSPFRules(strings.ToLower(record.SPFRules), rlog)

	case "APEXCNAME":
		if conf.cloudflare {
			rlog.Info().EmbedObject(internal.DCTL5009).Msg("")
			exitVal |= exitvals.CheckInfo
		}

	case "REDIR301", "REDIR302":
		if record.Target == "" {
			rlog.Error().Str("key", "target").EmbedObject(internal.DCTL1013).Msg("")
			exitVal |= exitvals.CheckError
		}
	default:
		rlog.Info().EmbedObject(internal.DCTL1016).Msg("")
		exitVal |= exitvals.CheckInfo
	}

	// Check use of underscore host names.
	exitVal |= conf.checkUnderscoreNames(record.Type, record.Host)

	if checkHostForDeniedChars(record.Host) {
		rlog.Error().Str("host", record.Host).EmbedObject(internal.DCTL1027).Msg("")
	}

	// The spec does not tell type cannot be variable, but if/when it is
	// reasoning about effects of applying a template becomes quite hard
	// if not impossible. Without dubt a variable type will cascade need
	// to use variable in all other parameters, and that means service
	// provider will basically grant oneself 100% full access to clients
	// DNS content. Domain Connect is expected to be powerful, but that
	// is too much power.
	if isVariable(record.Type) {
		rlog.Error().Str("type", record.Type).EmbedObject(internal.DCTL1009).Msg("")
		exitVal |= exitvals.CheckError
	}

	// A calid json int can be out of bounds in DNS
	ttl, ok := record.TTL.Uint32()
	if ok && MaxTTL < ttl {
		rlog.Error().Uint32("ttl", ttl).EmbedObject(internal.DCTL1015).Msg("")
		exitVal |= exitvals.CheckError
	} else if ok && conf.cloudflare && ttl == 0 {
		rlog.Info().EmbedObject(internal.DCTL5010).Msg("")
		exitVal |= exitvals.CheckInfo
	}
	if !ok && ttl == 0 && conf.inplace && 0 < conf.ttl && requiresTTL(record.Type) && isVariable(string(record.TTL)) {
		rlog.Info().Uint32("ttl", conf.ttl).Msg("adding ttl to the record")
		record.TTL.SetUint32(conf.ttl)
	}

	// Enforce Domain Connect spec
	if isVariable(record.GroupID) {
		rlog.Error().Str("groupId", record.GroupID).EmbedObject(internal.DCTL1009).Msg("")
		exitVal |= exitvals.CheckError
	}
	if isVariable(record.TxtCMP) {
		rlog.Error().Str("txtConflictMatchingPrefix", record.TxtCMP).EmbedObject(internal.DCTL1009).Msg("")
		exitVal |= exitvals.CheckError
	}

	// DNS provider specific checks
	if conf.cloudflare {
		if record.Essential != "" {
			rlog.Info().EmbedObject(internal.DCTL5011).Msg("")
			exitVal |= exitvals.CheckInfo
		}
	}

	exitVal |= findInvalidTemplateStrings(record, rlog)

	return exitVal
}

func checkHostForDeniedChars(host string) bool {
	if host == "*" || host == "@" {
		return false
	}
	for _, c := range host {
		switch c {
		case '.', '%':
			continue
		}
		if isDenied(c) {
			return true
		}
	}
	return false
}

func isInvalidProtocol(proto string) bool {
	// in SRV record
	switch strings.ToLower(proto) {
	case "_tcp", "_udp", "_tls":
		return false
	}
	return strings.Count(proto, "%") == 0
}

func requiresTTL(recordType string) bool {
	switch recordType {
	case strCNAME, "NS", "A", "AAAA", "TXT", "MX", "SRV":
		return true
	}
	return false
}

var mutuallyExclusive = []string{
	"data",
	"name",
	"pointsTo",
	"target",
}

func targetCheck(record *internal.Record, requiredField string, rlog zerolog.Logger) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK

	recordTypes := reflect.TypeOf(*record)

	for i := range recordTypes.NumField() {
		field := recordTypes.Field(i)

		jsonTag, ok := field.Tag.Lookup("json")
		if ok {
			csv := strings.Split(jsonTag, ",")
			if csv[0] == "" {
				rlog.Error().EmbedObject(internal.DCTL0007).Msg("")
				exitVal |= exitvals.CheckError
				continue
			}
			if csv[0] == requiredField {
				if reflect.ValueOf(*record).FieldByName(field.Name).String() == "" {
					rlog.Error().Str("field", requiredField).EmbedObject(internal.DCTL0008).Msg("")
					exitVal |= exitvals.CheckError
				}
				continue
			}
			if record.Type == "SRV" && csv[0] == "name" {
				continue
			}
			if slices.Contains(mutuallyExclusive, csv[0]) {
				if reflect.ValueOf(*record).FieldByName(field.Name).String() != "" {
					rlog.Info().Str("field", csv[0]).EmbedObject(internal.DCTL0009).Msg("")
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
		rlog.Error().Str("spfRules", "record spfRules is empty string").EmbedObject(internal.DCTL1013).Msg("")
		return exitvals.CheckError
	}
	if strings.HasPrefix(rules, "v=spf1") {
		rlog.Error().Str("spfRules", "v=spf1").EmbedObject(internal.DCTL1017).Msg("")
		exitVal |= exitvals.CheckError
	}
	if strings.HasSuffix(rules, "all") {
		rlog.Error().Str("spfRules", "all").EmbedObject(internal.DCTL1017).Msg("")
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
					rlog.Error().Str("field", "redirect").EmbedObject(internal.DCTL1018).Msg("")
					exitVal |= exitvals.CheckError
				}
				track.redirect = true
			case "exp":
				if track.exp {
					rlog.Error().Str("field", "exp").EmbedObject(internal.DCTL1018).Msg("")
					exitVal |= exitvals.CheckError
				}
				track.exp = true
			default:
				rlog.Error().Str("data", matches[1]).EmbedObject(internal.DCTL1017).Msg("")
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
			rlog.Error().Str("modifier", field).EmbedObject(internal.DCTL1017).Msg("")
			exitVal |= exitvals.CheckError
		}
	}

	return exitVal
}
