package libdctlint

import (
	"strings"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"

	"github.com/rs/zerolog"
)

func findInvalidTemplateStrings(record *internal.Record, rlog zerolog.Logger) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK

	exitVal |= checkSingleString(record.Host, rlog)
	exitVal |= checkSingleString(record.Name, rlog)
	exitVal |= checkSingleString(record.PointsTo, rlog)
	exitVal |= checkSingleString(record.Data, rlog)
	exitVal |= checkSingleString(record.TxtCMP, rlog)
	exitVal |= checkSingleString(record.Service, rlog)
	exitVal |= checkSingleString(record.Target, rlog)
	exitVal |= checkSingleString(record.SPFRules, rlog)

	return exitVal
}

func checkSingleString(input string, rlog zerolog.Logger) exitvals.CheckSeverity {
	withInVar := false

	for _, c := range input {
		if c == '%' {
			withInVar = !withInVar
			continue
		}
		if withInVar {
			if !(('0' <= c && '9' >= c) || ('a' <= c && 'z' >= c) || ('A' <= c && 'Z' >= c) || c == '_' || c == '-') {
				rlog.Warn().Str("invalid", input).EmbedObject(internal.DCTL1019).Msg("")
				return exitvals.CheckWarn
			}
		}
	}

	if strings.Contains(input, "%host%") {
		rlog.Warn().Str("invalid", input).EmbedObject(internal.DCTL1024).Msg("")
		return exitvals.CheckWarn
	}

	if withInVar {
		rlog.Error().Str("invalid", input).EmbedObject(internal.DCTL1020).Msg("")
		return exitvals.CheckError
	}

	return exitvals.CheckOK
}
