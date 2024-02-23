package libdctlint

import (
	"strings"

	"github.com/Domain-Connect/dc-template-linter/internal"

	"golang.org/x/exp/slices"
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

func (conf *Conf) checkUnderscoreNames(rrtype, host string) internal.CheckSeverity {
	rlog := conf.tlog.With().Str("type", rrtype).Str("link", "https://www.iana.org/assignments/dns-parameters/dns-parameters.txt").Logger()
	exitVal := internal.CheckOK

	for _, elem := range strings.Split(host, ".") {
		if len(elem) == 0 || elem[0] != '_' {
			continue
		}
		okTypes, ok := rfc8552[strings.ToLower(elem)]
		if !ok {
			rlog.Debug().Str("host", elem).Msg("global definition does not define this underscore host")
			exitVal |= internal.CheckDebug
			continue
		}

		templateType, ok := recordToType[strings.ToUpper(rrtype)]
		if !ok {
			rlog.Info().Str("host", elem).Msg("global definition does not have this host and type pair")
			exitVal |= internal.CheckInfo
			continue
		}

		if !slices.Contains(append([]uint16{TypeNS, TypeCNAME}, okTypes...), templateType) {
			rlog.Info().Str("host", elem).Msg("global definition does not have this host and type pair")
			exitVal |= internal.CheckInfo
		}
	}

	return exitVal
}
