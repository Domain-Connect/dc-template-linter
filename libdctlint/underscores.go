package libdctlint

import (
	"strings"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"

	"github.com/rs/zerolog"
)

func (conf *Conf) checkUnderscoreNames(rrtype, host string) exitvals.CheckSeverity {
	rlog := conf.tlog.With().Str("type", rrtype).Logger()
	exitVal := exitvals.CheckOK

	for elem := range strings.SplitSeq(host, ".") {
		location := strings.Index(elem, "_")
		if location > 1 && isStaticLabelUnderscore(elem) {
			elem := elem
			exitVal |= conf.emit(rlog, internal.DCTL1025, func(e *zerolog.Event) *zerolog.Event {
				return e.Str("host", elem)
			})
		}
	}

	return exitVal
}

func isStaticLabelUnderscore(elem string) bool {
	withInVariable := false

	for _, c := range elem {
		if c == '%' {
			withInVariable = !withInVariable
		}
		if !withInVariable && c == '_' {
			return true
		}
	}
	return false
}
