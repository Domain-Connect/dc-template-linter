// Package internal contains Domain Connect Template Linter messaging code values.
package internal

import (
	"fmt"

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
	DCTL1028: "warnPhishing together with syncPubKeyDomain has no practical relevance",
	DCTL1029: "syncPubKeyDomain not defined while syncBlock give impression it should be",
	DCTL1030: "template does not have any records",
	DCTL1031: "all record groupId values are the same",
	DCTL1032: "mix of defined empty and record groupId values",

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

func (dctl DCTL) MarshalZerologObject(e *zerolog.Event) {
	description, ok := dctlToString[dctl]
	if !ok {
		description = "invalid DCTL code"
	}
	e.Str("code", fmt.Sprintf("DCTL%04d", dctl)).Str("dctl_note", description)
}
