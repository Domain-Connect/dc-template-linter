package libdctlint

import (
	"bytes"
	"encoding/gob"

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"

	"github.com/cespare/xxhash/v2"
	"github.com/rs/zerolog"
)

func (conf *Conf) findDuplicates(record *internal.Record, rlog zerolog.Logger) exitvals.CheckSeverity {
	var bybuf bytes.Buffer

	enc := gob.NewEncoder(&bybuf)

	if err := enc.Encode(record); err != nil {
		rlog.Error().Err(err).Msg("could not encode record when finding duplicates")
		return exitvals.CheckError
	}

	checkSum := xxhash.Sum64(bybuf.Bytes())
	_, found := conf.duplicates[checkSum]

	if found {
		rlog.Warn().Uint64("checksum", checkSum).EmbedObject(internal.DCTL1023).Msg("")
		return exitvals.CheckWarn
	}

	conf.duplicates[checkSum] = true
	return exitvals.CheckOK
}
