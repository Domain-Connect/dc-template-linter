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

// in ascii smallest to greatest order
const allowedChars = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

func isDenied(needle rune) bool {
	start := 0
	end := len(allowedChars) - 1
	mid := len(allowedChars) / 2
	for start <= end {
		value := rune(allowedChars[mid])
		if value == needle {
			return false
		}
		if value > needle {
			end = mid - 1
			mid = (start + end) / 2
			continue
		}
		start = mid + 1
		mid = (start + end) / 2
	}
	return true
}

func checkSingleString(input string, rlog zerolog.Logger) exitvals.CheckSeverity {
	withInVar := false

	for _, c := range input {
		if c == '%' {
			withInVar = !withInVar
			continue
		}
		if withInVar {
			if isDenied(c) {
				rlog.Warn().Str("invalid", input).EmbedObject(internal.DCTL1019).Msg("")
				return exitvals.CheckWarn
			}
		}
	}

	if strings.Contains(input, "%host%") {
		rlog.Info().Str("invalid", input).EmbedObject(internal.DCTL1024).Msg("")
		return exitvals.CheckInfo
	}

	if withInVar {
		rlog.Error().Str("invalid", input).EmbedObject(internal.DCTL1020).Msg("")
		return exitvals.CheckError
	}

	return exitvals.CheckOK
}
