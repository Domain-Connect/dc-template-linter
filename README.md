## Domain Connect Template validation tool

This tool can be used to check if a template valid.

### Building

```
go install github.com/Domain-Connect/dc-template-linter@latest
```

### Running

```
git clone https://github.com/Domain-Connect/Templates.git &&
$GOPATH/bin/dc-template-linter ./Templates/*.json
```

When argument is not defined linter will read stdin.

```
curl -s https://raw.githubusercontent.com/Domain-Connect/Templates/master/acymailing.com.acymailer.json |
$GOPATH/bin/dc-template-linter -logos -loglevel debug
```

### Usage

```
$GOPATH/bin/dc-template-linter --help
Usage: dc-template-linter [options] <template.json> [...]
  -cloudflare
	use Cloudflare specific template rules
  -inplace
	inplace write back pretty-print
  -loglevel string
	loglevel can be one of: panic fatal error warn info debug trace (default "info")
  -logos
	check logo urls are reachable (requires network)
  -pretty
	pretty-print template json
  -version
	output version information and exit
Warning. -inplace and -pretty will remove zero priority MX and SRV fields
```
