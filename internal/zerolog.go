package internal

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func SetLoglevel(loglevel string) {
	level, err := zerolog.ParseLevel(loglevel)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid loglevel")
	}
	zerolog.SetGlobalLevel(level)
}
