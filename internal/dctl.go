// Package internal contains Domain Connect Template Linter messaging code values.
package internal

import (
	"fmt"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/rs/zerolog"
)

// DCTL codes type
type DCTL uint16

// DCTL code reservations
// 0000         unused
// 0001 - 0999  operating system and library errors
// 1000 - 3999  domain connect specific messages
// 5000 - 5200  cloudflare messages
const (
	DCTL0001 DCTL = 1
	DCTL0002 DCTL = 2
	DCTL0003 DCTL = 3
	DCTL0004 DCTL = 4
	DCTL0005 DCTL = 5
	DCTL0006 DCTL = 6
	DCTL0007 DCTL = 7
	DCTL0008 DCTL = 8
	DCTL0009 DCTL = 9

	DCTL1000 DCTL = 1000
	DCTL1001 DCTL = 1001
	DCTL1002 DCTL = 1002
	DCTL1003 DCTL = 1003
	DCTL1004 DCTL = 1004
	DCTL1005 DCTL = 1005
	DCTL1006 DCTL = 1006
	DCTL1007 DCTL = 1007
	DCTL1008 DCTL = 1008
	DCTL1009 DCTL = 1009
	DCTL1010 DCTL = 1010
	DCTL1011 DCTL = 1011
	DCTL1012 DCTL = 1012
	DCTL1013 DCTL = 1013
	DCTL1014 DCTL = 1014
	DCTL1015 DCTL = 1015
	DCTL1016 DCTL = 1016
	DCTL1017 DCTL = 1017
	DCTL1018 DCTL = 1018
	DCTL1019 DCTL = 1019
	DCTL1020 DCTL = 1020
	DCTL1021 DCTL = 1021
	DCTL1022 DCTL = 1022
	DCTL1023 DCTL = 1023
	DCTL1024 DCTL = 1024
	DCTL1025 DCTL = 1025
	DCTL1026 DCTL = 1026
	DCTL1027 DCTL = 1027
	DCTL1028 DCTL = 1028
	DCTL1029 DCTL = 1029
	DCTL1030 DCTL = 1030
	DCTL1031 DCTL = 1031
	DCTL1032 DCTL = 1032
	DCTL1033 DCTL = 1033
	DCTL1034 DCTL = 1034
	DCTL1035 DCTL = 1035
	DCTL1036 DCTL = 1036
	DCTL1037 DCTL = 1037

	DCTL5000 DCTL = 5000
	DCTL5001 DCTL = 5001
	DCTL5002 DCTL = 5002
	DCTL5003 DCTL = 5003
	DCTL5004 DCTL = 5004
	DCTL5005 DCTL = 5005
	DCTL5006 DCTL = 5006
	DCTL5007 DCTL = 5007
	DCTL5008 DCTL = 5008
	DCTL5009 DCTL = 5009
	DCTL5010 DCTL = 5010
	DCTL5011 DCTL = 5011
)

// DCTL descriptions
var dctlToString = map[DCTL]string{
	// operating system and library errors
	DCTL0001: "cannot open file",
	DCTL0002: "invalid loglevel",
	DCTL0003: "json error",
	DCTL0004: "write failed",
	DCTL0005: "could not create temporary file",
	DCTL0006: "file move failed",
	DCTL0007: "struct json tag missing",
	DCTL0008: "required field is missing",
	DCTL0009: "unnecessary field found",

	// domain connect specific messages
	DCTL1000: "ttl value exceeds maximum",
	DCTL1001: "<not in use after string-interger-variable values>",
	DCTL1002: "id contains invalid characters",
	DCTL1003: "file name does not use required pattern",
	DCTL1004: "duplicate provierId + serviceId detected",
	DCTL1005: "template field validation",
	DCTL1006: "use of negative version number",
	DCTL1007: "shared flag is deprecated, use sharedProviderName",
	DCTL1008: "sharedProviderName is in use without 'shared' compatibility",
	DCTL1009: "variable in invalid context",
	DCTL1010: "logo check failed",
	DCTL1011: "CNAME cannot be mixed with other record types",
	DCTL1012: "record host must not be @ when template hostRequired is false",
	DCTL1013: "key must not be empty",
	DCTL1014: "use SPFM instead of bare SPF record",
	DCTL1015: "invalid value",
	DCTL1016: "unexpeceted record type",
	DCTL1017: "spfRules contain invalid data",
	DCTL1018: "spfRules contain duplicate fields",
	DCTL1019: "variable contains invalid character",
	DCTL1020: "variable is not terminated",
	DCTL1021: "missing from iana definitions",
	DCTL1022: "invalid hostname",
	DCTL1023: "duplicate record entry",
	DCTL1024: "use of %host% variable name is problematic",
	DCTL1025: "use of underscore detected in a host: element",
	DCTL1026: "syncRedirectDomain must be a comma separated values without whitespaces",
	DCTL1027: "record host contains illegal character(s)",
	DCTL1028: "warnPhishing and syncPubKeyDomain are mutually exclusive",
	DCTL1029: "template does not have syncPubKeyDomain",
	DCTL1030: "template does not have any records",
	DCTL1031: "all record groupId values are the same",
	DCTL1032: "mix of empty and defined record groupId values",
	DCTL1033: "multiInstance with CNAME on @ does not make sense",
	DCTL1034: "address record must point to a valid IP or a variable",
	DCTL1035: "A record points to IPv6 address",
	DCTL1036: "AAAA record points to IPv4 address",
	DCTL1037: "hostRequired template should be combined with NS or CNAME record that uses host @ or empty",

	// cloudflare messages
	DCTL5000: "syncBlock is not supported",
	DCTL5001: "syncPubKeyDomain is required",
	DCTL5002: "sharedServiceName is not supported",
	DCTL5003: "syncRedirectDomain is not supported",
	DCTL5004: "multiInstance is not supported",
	DCTL5005: "warnPhishing is omitted",
	DCTL5006: "hostRequired is not supported",
	DCTL5007: "domains must use Cloudflares CNAME flattening setting",
	DCTL5008: "conflict matching is not supported",
	DCTL5009: "APEXCNAME is not supported",
	DCTL5010: "zero ttl is not honoured",
	DCTL5011: "essential is not supported",
}

// dctlLevel maps each DCTL code to its zerolog log level.
// The level determines both the zerolog logging severity and the exitvals.CheckSeverity bit.
var dctlLevel = map[DCTL]zerolog.Level{
	// operating system and library errors
	DCTL0001: zerolog.FatalLevel,
	DCTL0002: zerolog.FatalLevel,
	DCTL0003: zerolog.ErrorLevel,
	DCTL0004: zerolog.ErrorLevel,
	DCTL0005: zerolog.ErrorLevel,
	DCTL0006: zerolog.WarnLevel,
	DCTL0007: zerolog.ErrorLevel,
	DCTL0008: zerolog.ErrorLevel,
	DCTL0009: zerolog.InfoLevel,

	// domain connect specific messages
	DCTL1002: zerolog.ErrorLevel,
	DCTL1003: zerolog.ErrorLevel,
	DCTL1004: zerolog.ErrorLevel,
	DCTL1005: zerolog.ErrorLevel,
	DCTL1006: zerolog.InfoLevel,
	DCTL1007: zerolog.ErrorLevel,
	DCTL1008: zerolog.InfoLevel,
	DCTL1009: zerolog.ErrorLevel,
	DCTL1010: zerolog.WarnLevel,
	DCTL1011: zerolog.ErrorLevel,
	DCTL1012: zerolog.ErrorLevel,
	DCTL1013: zerolog.ErrorLevel,
	DCTL1014: zerolog.InfoLevel,
	DCTL1015: zerolog.ErrorLevel,
	DCTL1016: zerolog.InfoLevel,
	DCTL1017: zerolog.ErrorLevel,
	DCTL1018: zerolog.ErrorLevel,
	DCTL1019: zerolog.WarnLevel,
	DCTL1020: zerolog.ErrorLevel,
	DCTL1021: zerolog.InfoLevel,
	DCTL1022: zerolog.ErrorLevel,
	DCTL1023: zerolog.WarnLevel,
	DCTL1024: zerolog.InfoLevel,
	DCTL1025: zerolog.InfoLevel,
	DCTL1026: zerolog.WarnLevel,
	DCTL1027: zerolog.ErrorLevel,
	DCTL1028: zerolog.ErrorLevel,
	DCTL1029: zerolog.InfoLevel,
	DCTL1030: zerolog.ErrorLevel,
	DCTL1031: zerolog.InfoLevel,
	DCTL1032: zerolog.InfoLevel,
	DCTL1033: zerolog.WarnLevel,
	DCTL1034: zerolog.ErrorLevel,
	DCTL1035: zerolog.ErrorLevel,
	DCTL1036: zerolog.ErrorLevel,
	DCTL1037: zerolog.InfoLevel,

	// cloudflare messages
	DCTL5000: zerolog.ErrorLevel,
	DCTL5001: zerolog.ErrorLevel,
	DCTL5002: zerolog.InfoLevel,
	DCTL5003: zerolog.InfoLevel,
	DCTL5004: zerolog.InfoLevel,
	DCTL5005: zerolog.InfoLevel,
	DCTL5006: zerolog.InfoLevel,
	DCTL5007: zerolog.InfoLevel,
	DCTL5008: zerolog.InfoLevel,
	DCTL5009: zerolog.ErrorLevel,
	DCTL5010: zerolog.InfoLevel,
	DCTL5011: zerolog.InfoLevel,
}

// Level returns the zerolog.Level associated with this DCTL code.
// Unknown codes default to ErrorLevel.
func (dctl DCTL) Level() zerolog.Level {
	if level, ok := dctlLevel[dctl]; ok {
		return level
	}
	return zerolog.ErrorLevel
}

// Severity returns the exitvals.CheckSeverity bit that corresponds to this
// DCTL code's log level.
func (dctl DCTL) Severity() exitvals.CheckSeverity {
	switch dctl.Level() {
	case zerolog.DebugLevel, zerolog.TraceLevel:
		return exitvals.CheckDebug
	case zerolog.InfoLevel:
		return exitvals.CheckInfo
	case zerolog.WarnLevel:
		return exitvals.CheckWarn
	case zerolog.FatalLevel, zerolog.PanicLevel:
		return exitvals.CheckFatal
	default: // ErrorLevel
		return exitvals.CheckError
	}
}

func (dctl DCTL) MarshalZerologObject(e *zerolog.Event) {
	description, ok := dctlToString[dctl]
	if !ok {
		description = "invalid DCTL code"
	}
	e.Str("code", fmt.Sprintf("DCTL%04d", dctl)).Str("dctl_note", description)
}
