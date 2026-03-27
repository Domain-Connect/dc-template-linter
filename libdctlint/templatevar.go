package libdctlint

import (
	"strings"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"

	"github.com/rs/zerolog"
)

func findInvalidTemplateStrings(conf *Conf, record *internal.Record, rlog zerolog.Logger) exitvals.CheckSeverity {
	exitVal := exitvals.CheckOK

	exitVal |= checkSingleString(conf, record.Host, rlog)
	exitVal |= checkSingleString(conf, record.Name, rlog)
	exitVal |= checkSingleString(conf, record.PointsTo, rlog)
	exitVal |= checkSingleString(conf, record.Data, rlog)
	exitVal |= checkSingleString(conf, record.TxtCMP, rlog)
	exitVal |= checkSingleString(conf, record.Service, rlog)
	exitVal |= checkSingleString(conf, record.Target, rlog)
	exitVal |= checkSingleString(conf, record.SPFRules, rlog)

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

func checkSingleString(conf *Conf, input string, rlog zerolog.Logger) exitvals.CheckSeverity {
	withInVar := false

	for _, c := range input {
		if c == '%' {
			withInVar = !withInVar
			continue
		}
		if withInVar {
			if isDenied(c) {
				return conf.emit(rlog, internal.DCTL1019, func(e *zerolog.Event) *zerolog.Event {
					return e.Str("invalid", input)
				})
			}
		}
	}

	if strings.Contains(input, "%host%") {
		return conf.emit(rlog, internal.DCTL1024, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("invalid", input)
		})
	}

	if withInVar {
		return conf.emit(rlog, internal.DCTL1020, func(e *zerolog.Event) *zerolog.Event {
			return e.Str("invalid", input)
		})
	}

	return exitvals.CheckOK
}
