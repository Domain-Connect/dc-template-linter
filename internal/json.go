package internal

import (
	"encoding/json"
	"errors"
	"strconv"
	"sync"

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

// exitVal is a side channel to catch UnmarshalJSON failure. The standard
// golang json parser does not have means for extra values, and sending a
// message via error is not great either - it will stop parsing, which is
// annoying if early entry in records list is stringy entry but can be
// recovered while causing warning.
var exitVal CheckSeverity

// smuggledLog is similar side channel to exitVal but for json parser extra
// input rather than output.
var smuggledLog zerolog.Logger

// lock will ensure only one exitVal / logger pair is in use.
var mu sync.Mutex

// UnmarshalJSON can take string and integer version of an int and return
// int. When int is integer all happens without complaints, but a string int
// will cause warning and conversion to int. The json parsing will fail
// completely when string is not integer at all.
func (sint *SINT) UnmarshalJSON(b []byte) error {
	locked := mu.TryLock()
	if locked {
		return errors.New("BUG: SetLogger() call was not used")
	}
	exitVal = CheckOK

	if b[0] != '"' {
		err := json.Unmarshal(b, (*int)(sint))
		if err != nil {
			exitVal = CheckError
		}
		return err
	}
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		exitVal = CheckError
		return err
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		exitVal = CheckError
		return err
	}
	exitVal = CheckWarn
	smuggledLog.Warn().Str("value", s).Msg("do not quote an integer, it makes it string")
	*sint = SINT(i)
	return nil
}

func SetLogger(l zerolog.Logger) {
	mu.Lock()
	smuggledLog = l
}

func GetUnmarshalStatus() CheckSeverity {
	defer mu.Unlock()
	return exitVal
}
