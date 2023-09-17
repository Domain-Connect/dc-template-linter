package main

/*
 * This is a Domain Connect template lint tool to validate contents of a
 * template file. These templates are usually found from
 * https://github.com/domain-connect/templates
 *
 * Questions about the tool can be sent to <domain-connect@cloudflare.com>
 */

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Domain-Connect/dc-template-linter/libdctlint"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func setLoglevel(loglevel string) {
	level, err := zerolog.ParseLevel(loglevel)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid loglevel")
	}
	zerolog.SetGlobalLevel(level)
}

func main() {
	// Init logging. Essentially colors or no colors?
	if isatty.IsTerminal(os.Stderr.Fd()) {
		log.Logger = log.Output(
			zerolog.ConsoleWriter{
				Out:        os.Stderr,
				TimeFormat: time.RFC3339,
			},
		)
	} else {
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	}

	// Command line option handling
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <template.json> [...]\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "Warning. -inplace and -pretty will remove zero priority MX and SRV fields\n")
	}
	checkLogos := flag.Bool("logos", false, "check logo urls are reachable (requires network)")
	cloudflare := flag.Bool("cloudflare", false, "use Cloudflare specific template rules")
	inplace := flag.Bool("inplace", false, "inplace write back pretty-print")
	prettyPrint := flag.Bool("pretty", false, "pretty-print template json")
	loglevel := flag.String("loglevel", "info", "loglevel can be one of: panic fatal error warn info debug trace")
	version := flag.Bool("version", false, "output version information and exit")
	flag.Parse()

	// Did user want to know version
	if *version {
		fmt.Printf("dc-template-linter version %d\n", dcTemplateLinterVersion)
		os.Exit(0)
	}

	// Runtime init
	setLoglevel(*loglevel)
	exitVal := libdctlint.CheckOK

	if flag.NArg() < 1 {
		// No arguments, read from stdin
		conf := libdctlint.NewConf(
			*checkLogos,
			*cloudflare,
			false,
			*prettyPrint,
		)
		if *inplace {
			log.Warn().Msg("disabling -inplace")
		}
		log.Debug().Msg("reading from stdin")
		conf.FileName = "/dev/stdin"
		reader := bufio.NewReader(os.Stdin)
		exitVal = conf.CheckTemplate(reader)
	} else {
		// Each argument is expected to be a template file,
		// loop over them.
		conf := libdctlint.NewConf(
			*checkLogos,
			*cloudflare,
			*inplace,
			*prettyPrint,
		)
		for _, arg := range flag.Args() {
			conf.FileName = arg
			f, err := os.Open(arg)
			if err != nil {
				log.Error().Err(err).Msg("cannot open file")
				exitVal = 1
				continue
			}
			log.Debug().Str("template", arg).Msg("processing template")
			exitVal |= conf.CheckTemplate(bufio.NewReader(f))
			f.Close()
		}
	}
	os.Exit(int(exitVal))
}
