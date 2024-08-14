package internal

import (
	"encoding/json"
	"fmt"
	"strconv"
)

type Template struct {
	ProviderID          string  `json:"providerId" validate:"required,min=1,max=64"`
	ProviderName        string  `json:"providerName" validate:"required,min=1,max=64"`
	ServiceID           string  `json:"serviceId" validate:"required,min=1,max=64"`
	ServiceName         string  `json:"serviceName" validate:"required,min=1,max=255"`
	Version             SINT    `json:"version,omitempty"`
	Logo                string  `json:"logoUrl,omitempty"`
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
	GroupID   string `json:"groupId,omitempty" validate:"min=1"`
	Essential string `json:"essential,omitempty" validate:"oneof=Always OnApply"`
	Host      string `json:"host,omitempty" validate:"min=1,max=255"`
	Name      string `json:"name,omitempty" validate:"hostname"`
	PointsTo  string `json:"pointsTo,omitempty" validate:"min=1,max=255"`
	TTL       SINT   `json:"ttl,omitempty" validate:"required,min=1"`
	Data      string `json:"data,omitempty" validate:"min=1"`
	TxtCMM    string `json:"txtConflictMatchingMode,omitempty" validate:"oneof=None All Prefix"`
	TxtCMP    string `json:"txtConflictMatchingPrefix,omitempty" validate:"min=1"`
	Priority  SINT   `json:"priority,omitempty"`
	Weight    SINT   `json:"weight,omitempty"`
	Port      SINT   `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty" validate:"min=1"`
	Service   string `json:"service,omitempty" validate:"min=1"`
	Target    string `json:"target,omitempty" validate:"min=1"`
	SPFRules  string `json:"spfRules,omitempty" validate:"min=1"`
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

func (sint *SINT) Inc() {
	i, err := strconv.Atoi(string(*sint))
	if err != nil {
		return
	}
	i++
	s := fmt.Sprintf("%d", i)
	*sint = SINT(s)
}

func (sint *SINT) Uint32() (uint32, bool) {
	var i uint32
	err := json.Unmarshal([]byte(*sint), &i)
	if err != nil {
		return i, false
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
		return 0, false
	}
	return uint16(i), true
}
