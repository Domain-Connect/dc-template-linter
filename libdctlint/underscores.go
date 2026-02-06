package libdctlint

import (
	"slices"
	"strings"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"
)

const (
	TypeNS         uint16 = 2
	TypeCNAME      uint16 = 5
	TypeNULL       uint16 = 10
	TypeTXT        uint16 = 16
	TypeSRV        uint16 = 33
	TypeTLSA       uint16 = 52
	TypeSMIMEA     uint16 = 53
	TypeOPENPGPKEY uint16 = 61
	TypeSVCB       uint16 = 64
	TypeHTTPS      uint16 = 65
	TypeURI        uint16 = 256
)

var recordToType = map[string]uint16{
	"NS":         TypeNS,
	"CNAME":      TypeCNAME,
	"NULL":       TypeNULL,
	"TXT":        TypeTXT,
	"SRV":        TypeSRV,
	"TLSA":       TypeTLSA,
	"SMIMEA":     TypeSMIMEA,
	"OPENPGPKEY": TypeOPENPGPKEY,
	"SVCB":       TypeSVCB,
	"HTTPS":      TypeHTTPS,
	"URI":        TypeURI,
}

var rfc8552 = map[string][]uint16{
	"_acct":                    {TypeURI},
	"_acme-challenge":          {TypeTXT},
	"_dane":                    {TypeTLSA},
	"_dccp":                    {TypeSRV, TypeURI},
	"_dmarc":                   {TypeTXT},
	"_dns":                     {TypeSVCB},
	"_domainkey":               {TypeTXT},
	"_email":                   {TypeURI},
	"_ems":                     {TypeURI},
	"_fax":                     {TypeURI},
	"_ft":                      {TypeURI},
	"_h323":                    {TypeURI},
	"_https":                   {TypeHTTPS},
	"_http":                    {TypeSRV},
	"_iax":                     {TypeURI},
	"_ical-access":             {TypeURI},
	"_ical-sched":              {TypeURI},
	"_ifax":                    {TypeURI},
	"_im":                      {TypeURI},
	"_ipv6":                    {TypeSRV},
	"_ldap":                    {TypeSRV},
	"_mms":                     {TypeURI},
	"_mta-sts":                 {TypeTXT},
	"_ocsp":                    {TypeSRV},
	"_openpgpkey":              {TypeOPENPGPKEY},
	"_pres":                    {TypeURI},
	"_pstn":                    {TypeURI},
	"_sctp":                    {TypeSRV, TypeTLSA, TypeURI},
	"_sip":                     {TypeSRV, TypeURI},
	"_smimecert":               {TypeSMIMEA},
	"_sms":                     {TypeURI},
	"_spf":                     {TypeTXT},
	"_sztp":                    {TypeTXT},
	"_ta-*":                    {TypeNULL},
	"_tcp":                     {TypeTXT, TypeSRV, TypeTLSA, TypeURI},
	"_udp":                     {TypeTXT, TypeSRV, TypeTLSA, TypeURI},
	"_unifmsg":                 {TypeURI},
	"_validation-contactemail": {TypeTXT},
	"_validation-contactphone": {TypeTXT},
	"_vcard":                   {TypeURI},
	"_videomsg":                {TypeURI},
	"_voicemsg":                {TypeURI},
	"_voice":                   {TypeURI},
	"_vouch":                   {TypeTXT},
	"_vpim":                    {TypeURI},
	"_web":                     {TypeURI},
	"_xmpp":                    {TypeSRV, TypeURI},
}

func (conf *Conf) checkUnderscoreNames(rrtype, host string) exitvals.CheckSeverity {
	rlog := conf.tlog.With().Str("type", rrtype).Logger()
	exitVal := exitvals.CheckOK

	for _, elem := range strings.Split(host, ".") {
		location := strings.Index(elem, "_")
		if location > 1 && isStaticLabelUnderscore(elem) {
			rlog.Info().Str("host", elem).EmbedObject(internal.DCTL1025).Msg("")
			exitVal |= exitvals.CheckInfo
			continue
		}

		if len(elem) == 0 || elem[0] != '_' {
			continue
		}
		okTypes, ok := rfc8552[strings.ToLower(elem)]
		if !ok {
			rlog.Debug().Str("host", elem).EmbedObject(internal.DCTL1021).Msg("")
			exitVal |= exitvals.CheckDebug
			continue
		}

		templateType, ok := recordToType[strings.ToUpper(rrtype)]
		if !ok {
			rlog.Info().Str("host", elem).EmbedObject(internal.DCTL1021).Msg("")
			exitVal |= exitvals.CheckInfo
			continue
		}

		if !slices.Contains(append([]uint16{TypeNS, TypeCNAME}, okTypes...), templateType) {
			rlog.Info().Str("host", elem).EmbedObject(internal.DCTL1021).Msg("")
			exitVal |= exitvals.CheckInfo
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
