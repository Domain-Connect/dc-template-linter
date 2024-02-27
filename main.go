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
	"runtime/debug"
	"time"

	"github.com/Domain-Connect/dc-template-linter/internal"
	"github.com/Domain-Connect/dc-template-linter/libdctlint"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var GitCommit = func() string {
	vcsrevision := "<unknown>"
	vcsmodified := ""
	vcstime := "0000-00-00T00:00:00Z"

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				vcsrevision = setting.Value
			case "vcs.modified":
				if setting.Value == "true" {
					vcsmodified = " (dirty)"
				}
			case "vcs.time":
				vcstime = setting.Value
			}
		}
	}
	return vcsrevision + vcsmodified + " " + vcstime
}()

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
	increment := flag.Bool("increment", false, "increment template version, useful when pretty-printing")
	prettyPrint := flag.Bool("pretty", false, "pretty-print template json")
	loglevel := flag.String("loglevel", "info", "loglevel can be one of: panic fatal error warn info debug trace")
	toleration := flag.String("tolerate", "info", "non-zero return loglevel treshold: any error warn info debug none")
	version := flag.Bool("version", false, "output version information and exit")
	flag.Parse()

	// Did user want to know version
	if *version {
		fmt.Printf("dc-template-linter version %s\n", GitCommit)
		os.Exit(0)
	}

	// Runtime init
	internal.SetLoglevel(*loglevel)
	exitVal := internal.CheckOK

	if flag.NArg() < 1 {
		// No arguments, read from stdin
		conf := libdctlint.NewConf(
			*checkLogos,
			*cloudflare,
			false, // inplace will not work with stdin
			*increment,
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
			*increment,
			*prettyPrint,
		)
		for _, arg := range flag.Args() {
			conf.FileName = arg
			f, err := os.Open(arg)
			if err != nil {
				log.Error().Err(err).Msg("cannot open file")
				exitVal = internal.CheckError
				continue
			}
			log.Debug().Str("template", arg).Msg("processing template")
			exitVal |= conf.CheckTemplate(bufio.NewReader(f))
			f.Close()
		}
	}

	switch *toleration {
	case "any":
		exitVal = internal.CheckOK
	case "error":
		exitVal &= internal.CheckFatal
	case "warn":
		exitVal &= internal.CheckFatal | internal.CheckError
	case "info":
		exitVal &= internal.CheckFatal | internal.CheckError | internal.CheckWarn
	case "debug":
		exitVal &= internal.CheckFatal | internal.CheckError | internal.CheckWarn | internal.CheckInfo
	default:
		// none
	}

	os.Exit(int(exitVal))
}
