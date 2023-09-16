package internal

import (
	"encoding/json"
	"strconv"

	"github.com/rs/zerolog"
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
	TTL       SINT   `json:"ttl" validate:"required,min=1"`
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

type SINT int

var Log zerolog.Logger
var ExitVal int

func (sint *SINT) UnmarshalJSON(b []byte) error {
	ExitVal = 0
	if b[0] != '"' {
		return json.Unmarshal(b, (*int)(sint))
	}
	var s string
	ExitVal = 2
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	ExitVal = 1
	Log.Warn().Str("value", s).Msg("do not quote an integer, it makes it string")
	*sint = SINT(i)
	return nil
}
