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

	"github.com/Domain-Connect/dc-template-linter/exitvals"
	"github.com/Domain-Connect/dc-template-linter/internal"
	"github.com/Domain-Connect/dc-template-linter/libdctlint"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

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
		fmt.Fprintf(os.Stderr, "You can find long DCTL explanations in wiki\n")
		fmt.Fprintf(os.Stderr, "e.g., https://github.com/Domain-Connect/dc-template-linter/wiki/DCTL1001\n")
	}
	checkLogos := flag.Bool("logos", false, "check logo urls are reachable (requires network)")
	cloudflare := flag.Bool("cloudflare", false, "use Cloudflare specific template rules")
	inplace := flag.Bool("inplace", false, "inplace write back pretty-print")
	increment := flag.Bool("increment", false, "increment template version, useful when pretty-printing")
	prettyPrint := flag.Bool("pretty", false, "pretty-print template json")
	loglevel := flag.String("loglevel", "info", "loglevel can be one of: panic fatal error warn info debug trace")
	toleration := flag.String("tolerate", "info", "non-zero return loglevel treshold: any error warn info debug none")
	ttl := flag.Uint("ttl", 0, "-inplace ttl fix value to be used when template ttl is zero or invalid")
	version := flag.Bool("version", false, "output version information and exit")
	flag.Parse()

	// Did user want to know version
	if *version {
		fmt.Printf("dc-template-linter version %d\n", dcTemplateLinterVersion)
		os.Exit(0)
	}

	// Runtime init
	internal.SetLoglevel(*loglevel)
	exitVal := exitvals.CheckOK

	if libdctlint.MaxTTL < *ttl {
		log.Fatal().Uint("ttl", *ttl).Uint("max", libdctlint.MaxTTL).EmbedObject(internal.DCTL1000).Msg("")
	}

	conf := libdctlint.NewConf().
		SetCheckLogos(*checkLogos).
		SetPrettyPrint(*prettyPrint).
		SetCloudflare(*cloudflare)

	if flag.NArg() < 1 {
		log.Debug().Msg("reading from stdin")
		conf.SetFilename("/dev/stdin")
		reader := bufio.NewReader(os.Stdin)
		exitVal = conf.CheckTemplate(reader)
	} else {
		conf.SetInplace(*inplace).
			SetTTL(*ttl).
			SetIncrement(*increment)

		for _, arg := range flag.Args() {
			conf.SetFilename(arg)
			f, err := os.Open(arg)
			if err != nil {
				log.Error().Err(err).EmbedObject(internal.DCTL0001).Msg("")
				exitVal = exitvals.CheckError
				continue
			}
			log.Debug().Str("template", arg).Msg("processing template")
			exitVal |= conf.CheckTemplate(bufio.NewReader(f))
			f.Close()
		}
	}

	switch *toleration {
	case "any":
		exitVal = exitvals.CheckOK
	case "error":
		exitVal &= exitvals.CheckFatal
	case "warn":
		exitVal &= exitvals.CheckFatal | exitvals.CheckError
	case "info":
		exitVal &= exitvals.CheckFatal | exitvals.CheckError | exitvals.CheckWarn
	case "debug":
		exitVal &= exitvals.CheckFatal | exitvals.CheckError | exitvals.CheckWarn | exitvals.CheckInfo
	default:
		// none
	}

	os.Exit(int(exitVal))
}
