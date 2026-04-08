package libdctlint

import (
	"net"
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
	rlog := conf.tlog.With().Str("groupid", record.GroupID).Int("record", rnum+1).Str("type", record.Type).Logger()
	rlog.Debug().Str("host", record.Host).Msg("check record")

	exitVal |= conf.findDuplicates(record, rlog)

	// Try to catch CNAME usage with other records
	if t, ok := conflictingTypes[record.GroupID+"/"+record.Host]; ok && (t == strCNAME || record.Type == strCNAME) {
		host := record.Host
		exitVal |= conf.emit(rlog, internal.DCTL1011, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("host", host).Str("othertype", t)
		})
	}
	conflictingTypes[record.GroupID+"/"+record.Host] = record.Type

	// The type specific checks are mostly from the Domain Connect spec
	switch record.Type {
	case strCNAME, "NS":
		if record.Host == "@" {
			if template.MultiInstance && record.Type != "NS" {
				exitVal |= conf.emit(rlog, internal.DCTL1033, nil)
			}
			if conf.cloudflare {
				exitVal |= conf.emit(rlog, internal.DCTL5007, nil)
			} else if !template.HostRequired {
				exitVal |= conf.emit(rlog, internal.DCTL1012, nil)
			}
		}
		if record.Host == "" {
			exitVal |= conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("key", "host")
			})
		}
		exitVal |= targetCheck(conf, record, "pointsTo", rlog)
	case "A", "AAAA":
		if record.Host == "" {
			exitVal |= conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("key", "host")
			})
		}
		if !isVariable(record.PointsTo) {
			ip := net.ParseIP(record.PointsTo)
			if ip == nil {
				pointsTo := record.PointsTo
				exitVal |= conf.emit(rlog, internal.DCTL1034, func(e *zerolog.Event) *zerolog.Event {
					return e.Str("pointsTo", pointsTo)
				})
			} else {
				if record.Type == "A" && ip.To4() == nil {
					pointsTo := record.PointsTo
					exitVal |= conf.emit(rlog, internal.DCTL1035, func(e *zerolog.Event) *zerolog.Event {
						return e.Str("pointsTo", pointsTo)
					})
				}
				if record.Type == "AAAA" && ip.To4() != nil {
					pointsTo := record.PointsTo
					exitVal |= conf.emit(rlog, internal.DCTL1036, func(e *zerolog.Event) *zerolog.Event {
						return e.Str("pointsTo", pointsTo)
					})
				}
			}
		}

	case "TXT":
		if record.Host == "" {
			exitVal |= conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("key", "host")
			})
		}
		exitVal |= targetCheck(conf, record, "data", rlog)
		if conf.cloudflare {
			if record.TxtCMM != "" || record.TxtCMM == "None" {
				exitVal |= conf.emit(rlog, internal.DCTL5008, func(e *zerolog.Event) *zerolog.Event {
					return e.Str("key", "txtConflictMatchingMode")
				})
			}
			if record.TxtCMP != "" {
				exitVal |= conf.emit(rlog, internal.DCTL5008, func(e *zerolog.Event) *zerolog.Event {
					return e.Str("key", "txtConflictMatchingPrefix")
				})
			}
		} else if record.TxtCMM == "Prefix" && record.TxtCMP == "" {
			exitVal |= conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("key", "txtConflictMatchingPrefix")
			})
		}
		if strings.Contains(record.Data, "v=spf1") {
			exitVal |= conf.emit(rlog, internal.DCTL1014, nil)
		}

	case "MX":
		if record.Host == "" {
			exitVal |= conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("key", "host")
			})
		}
		exitVal |= targetCheck(conf, record, "pointsTo", rlog)
		if priority, ok := record.Priority.Uint32(); !ok || max31b < priority {
			exitVal |= conf.emit(rlog, internal.DCTL1015, func(e *zerolog.Event) *zerolog.Event {
				return e.Uint32("priority", priority)
			})
		}

	case "SRV":
		exitVal |= targetCheck(conf, record, "target", rlog)
		if isInvalidProtocol(record.Protocol) {
			proto := record.Protocol
			exitVal |= conf.emit(rlog, internal.DCTL1015, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("protocol", proto)
			})
		}
		if priority, ok := record.Priority.Uint32(); !ok || max31b < priority {
			exitVal |= conf.emit(rlog, internal.DCTL1015, func(e *zerolog.Event) *zerolog.Event {
				return e.Uint32("priority", priority)
			})
		}
		if record.Service == "" {
			exitVal |= conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("key", "service")
			})
		}
		if weight, ok := record.Weight.Uint32(); !ok || max31b < weight {
			exitVal |= conf.emit(rlog, internal.DCTL1015, func(e *zerolog.Event) *zerolog.Event {
				return e.Uint32("weight", weight)
			})
		}
		if port, ok := record.Port.Uint16(); !ok || max16b < port {
			exitVal |= conf.emit(rlog, internal.DCTL1015, func(e *zerolog.Event) *zerolog.Event {
				return e.Uint16("port", port)
			})
		}

	case "SPFM":
		if record.Host == "" {
			exitVal |= conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("key", "host")
			})
		}
		exitVal |= checkSPFRules(conf, strings.ToLower(record.SPFRules), rlog)

	case "APEXCNAME":
		if conf.cloudflare {
			exitVal |= conf.emit(rlog, internal.DCTL5009, nil)
		} else {
			exitVal |= conf.emit(rlog, internal.DCTL1038, nil)
		}
		if record.PointsTo == "" {
			exitVal |= conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("key", "pointsTo")
			})
		}

	case "REDIR301", "REDIR302":
		exitVal |= conf.emit(rlog, internal.DCTL1038, nil)
		if record.Target == "" {
			exitVal |= conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("key", "target")
			})
		}
		if record.Host != "" {
			exitVal |= targetCheck(conf, record, "target", rlog)
		}
	default:
		exitVal |= conf.emit(rlog, internal.DCTL1016, nil)
	}

	// Check use of underscore host names.
	exitVal |= conf.checkUnderscoreNames(record.Type, record.Host)

	if checkHostForDeniedChars(record.Host) {
		host := record.Host
		exitVal |= conf.emit(rlog, internal.DCTL1027, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("host", host)
		})
	}

	// The spec does not tell type cannot be variable, but if/when it is
	// reasoning about effects of applying a template becomes quite hard
	// if not impossible. Without dubt a variable type will cascade need
	// to use variable in all other parameters, and that means service
	// provider will basically grant oneself 100% full access to clients
	// DNS content. Domain Connect is expected to be powerful, but that
	// is too much power.
	if isVariable(record.Type) {
		recType := record.Type
		exitVal |= conf.emit(rlog, internal.DCTL1009, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("type", recType)
		})
	}

	// A calid json int can be out of bounds in DNS
	ttl, ok := record.TTL.Uint32()
	if ok && MaxTTL < ttl {
		exitVal |= conf.emit(rlog, internal.DCTL1015, func(e *zerolog.Event) *zerolog.Event {
			return e.Uint32("ttl", ttl)
		})
	} else if ok && conf.cloudflare && ttl == 0 {
		exitVal |= conf.emit(rlog, internal.DCTL5010, nil)
	}
	if !ok && ttl == 0 && conf.inplace && 0 < conf.ttl && requiresTTL(record.Type) && isVariable(string(record.TTL)) {
		rlog.Info().Uint32("ttl", conf.ttl).Msg("adding ttl to the record")
		record.TTL.SetUint32(conf.ttl)
	}

	// Enforce Domain Connect spec
	if isVariable(record.GroupID) {
		groupID := record.GroupID
		exitVal |= conf.emit(rlog, internal.DCTL1009, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("groupId", groupID)
		})
	}
	if isVariable(record.TxtCMP) {
		txtCMP := record.TxtCMP
		exitVal |= conf.emit(rlog, internal.DCTL1009, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("txtConflictMatchingPrefix", txtCMP)
		})
	}

	// DNS provider specific checks
	if conf.cloudflare {
		if record.Essential != "" {
			exitVal |= conf.emit(rlog, internal.DCTL5011, nil)
		}
	}

	exitVal |= findInvalidTemplateStrings(conf, record, rlog)
	trailingVariable(conf, record.Host, rnum)

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
	case strCNAME, "NS", "A", "AAAA", "TXT", "MX", "SRV", "APEXCNAME":
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

func targetCheck(conf *Conf, record *internal.Record, requiredField string, rlog zerolog.Logger) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK

	recordTypes := reflect.TypeOf(*record)

	for i := range recordTypes.NumField() {
		field := recordTypes.Field(i)

		jsonTag, ok := field.Tag.Lookup("json")
		if ok {
			csv := strings.Split(jsonTag, ",")
			if csv[0] == "" {
				exitVal |= conf.emit(rlog, internal.DCTL0007, nil)
				continue
			}
			if csv[0] == requiredField {
				if reflect.ValueOf(*record).FieldByName(field.Name).String() == "" {
					rf := requiredField
					exitVal |= conf.emit(rlog, internal.DCTL0008, func(e *zerolog.Event) *zerolog.Event {
						return e.Str("field", rf)
					})
				}
				continue
			}
			if record.Type == "SRV" && csv[0] == "name" {
				continue
			}
			if slices.Contains(mutuallyExclusive, csv[0]) {
				if reflect.ValueOf(*record).FieldByName(field.Name).String() != "" {
					fieldName := csv[0]
					exitVal |= conf.emit(rlog, internal.DCTL0009, func(e *zerolog.Event) *zerolog.Event {
						return e.Str("field", fieldName)
					})
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

func checkSPFRules(conf *Conf, rules string, rlog zerolog.Logger) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK

	if rules == "" {
		return conf.emit(rlog, internal.DCTL1013, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("spfRules", "record spfRules is empty string")
		})
	}
	if strings.HasPrefix(rules, "v=spf1") {
		exitVal |= conf.emit(rlog, internal.DCTL1017, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("spfRules", "v=spf1")
		})
	}
	if strings.HasSuffix(rules, "all") {
		exitVal |= conf.emit(rlog, internal.DCTL1017, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("spfRules", "all")
		})
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
					exitVal |= conf.emit(rlog, internal.DCTL1018, func(e *zerolog.Event) *zerolog.Event {
						return e.Str("field", "redirect")
					})
				}
				track.redirect = true
			case "exp":
				if track.exp {
					exitVal |= conf.emit(rlog, internal.DCTL1018, func(e *zerolog.Event) *zerolog.Event {
						return e.Str("field", "exp")
					})
				}
				track.exp = true
			default:
				data := matches[1]
				exitVal |= conf.emit(rlog, internal.DCTL1017, func(e *zerolog.Event) *zerolog.Event {
					return e.Str("data", data)
				})
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
			modifier := field
			exitVal |= conf.emit(rlog, internal.DCTL1017, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("modifier", modifier)
			})
		}
	}

	return exitVal
}
