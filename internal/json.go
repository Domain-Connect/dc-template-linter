package internal

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Template struct {
	ProviderID          string  `json:"providerId" validate:"required,min=1,max=64"`
	ProviderName        string  `json:"providerName" validate:"required,min=1,max=64"`
	ServiceID           string  `json:"serviceId" validate:"required,min=1,max=64"`
	ServiceName         string  `json:"serviceName" validate:"required,min=1,max=255"`
	Version             uint    `json:"version,omitempty"`
	Logo                string  `json:"logoUrl,omitempty" validate:"omitempty,http_url"`
	Description         string  `json:"description,omitempty"`
	VariableDescription string  `json:"variableDescription,omitempty"`
	Shared              bool    `json:"shared,omitempty"` /* deprecated */
	SyncBlock           bool    `json:"syncBlock,omitempty"`
	SharedProviderName  bool    `json:"sharedProviderName,omitempty"`
	SharedServiceName   bool    `json:"sharedServiceName,omitempty"`
	SyncPubKeyDomain    string  `json:"syncPubKeyDomain,omitempty" validate:"max=255"`
	SyncRedirectDomain  string  `json:"syncRedirectDomain,omitempty"`
	MultiInstance       bool    `json:"multiInstance,omitempty"`
	WarnPhishing        bool    `json:"warnPhishing,omitempty"`
	HostRequired        bool    `json:"hostRequired,omitempty"`
	Records             Records `json:"records"`
}

type Records []Record

type Record struct {
	Type      string `json:"type" validate:"required,min=1,max=16"`
	GroupID   string `json:"groupId,omitempty" validate:"omitempty"`
	Essential string `json:"essential,omitempty" validate:"omitempty,oneof=Always OnApply"`
	Host      string `json:"host,omitempty" validate:"omitempty,max=255"`
	Name      string `json:"name,omitempty" validate:"omitempty,max=63"`
	PointsTo  string `json:"pointsTo,omitempty" validate:"omitempty,max=255"`
	TTL       SINT   `json:"ttl,omitempty" validate:"omitempty,min=1"`
	Data      string `json:"data,omitempty" validate:"required_if=Type TXT"`
	TxtCMM    string `json:"txtConflictMatchingMode,omitempty" validate:"omitempty,oneof=None All Prefix"`
	TxtCMP    string `json:"txtConflictMatchingPrefix,omitempty" validate:"omitempty"`
	Priority  SINT   `json:"priority,omitempty validate:"required_if=Type SRV"`
	Weight    SINT   `json:"weight,omitempty validate:"required_if=Type SRV""`
	Port      SINT   `json:"port,omitempty validate:"required_if=Type SRV""`
	Protocol  string `json:"protocol,omitempty" validate:"required_if=Type SRV"`
	Service   string `json:"service,omitempty" validate:"required_if=Type SRV"`
	Target    string `json:"target,omitempty" validate:"required_if=Type SRV"`
	SPFRules  string `json:"spfRules,omitempty" validate:"omitempty,min=1"`
}

type SINT string

// UnmarshalJSON can take string and integer version of an int and return
// int. When int is integer all happens without complaints, but a string int
// will cause warning and conversion to int. The json parsing will fail
// completely when string is not integer at all.
func (sint *SINT) UnmarshalJSON(b []byte) error {
	s, err := strconv.Unquote(string(b))
	if err != nil {
		// cannot unquote, value is numeric
		*sint = SINT(b)
		return nil
	}
	*sint = SINT(s)
	return nil
}

func (sint *SINT) MarshalJSON() ([]byte, error) {
	s := string(*sint)
	c := s[0]
	if (c < '0' || '9' < c) && (c != '%' || s[len(s)-1] != '%') {
		return []byte{}, fmt.Errorf("invalid string-interger-variable: %s", string(*sint))
	}
	quoted := fmt.Sprintf("\"%s\"", *sint)
	return []byte(quoted), nil
}

func (sint *SINT) Uint32() (uint32, bool) {
	var i uint32
	err := json.Unmarshal([]byte(*sint), &i)
	if err != nil {
		return i, strings.Count(string(*sint), "%") > 1
	}
	return i, true
}

func (sint *SINT) SetUint32(value uint32) {
	s := fmt.Sprintf("%d", value)
	*sint = SINT(s)
}

func (sint *SINT) Uint16() (uint16, bool) {
	i, err := strconv.Atoi(string(*sint))
	if err != nil {
		return 0, strings.Count(string(*sint), "%") > 1
	}
	return uint16(i), true
}
