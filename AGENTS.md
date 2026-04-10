# AGENTS.md - Domain Connect Template Linter

## Project Overview

This is a **Go** project that provides a command-line tool for validating Domain Connect templates.

Domain Connect is an open standard that simplifies the process of connecting domain names to services by allowing Service Providers to automatically configure DNS settings through templates. This linter validates these templates against the official Domain Connect specification.

## Language and Build

- **Language**: Go (version 1.24.0)
- **Module**: `github.com/Domain-Connect/dc-template-linter`
- **Build**: Standard Go build (`go build`, `go install`)

## Code Style

All `.go` source files **must** be formatted using:

```bash
gofmt -s -w <file.go>
```

This ensures consistent code formatting across the project. The `-s` flag simplifies code, and `-w` writes the result back to the file.

## Key Dependencies

- `github.com/go-playground/validator/v10` - JSON struct validation
- `github.com/rs/zerolog` - Structured logging
- `github.com/cespare/xxhash/v2` - Hashing for duplicate detection
- `github.com/THREATINT/go-net` - Network utilities

## Project Structure

```
.
├── main.go                 # CLI entry point
├── go.mod, go.sum          # Go module files
├── internal/               # Internal packages
│   ├── dctl.go            # Domain Connect template lint definitions
│   ├── json.go            # JSON utilities
│   ├── utils.go           # General utilities
│   ├── version.go         # Version information
│   └── zerolog.go         # Logging setup
├── libdctlint/             # Core linting library
│   ├── lib.go             # Main linting logic
│   ├── config.go          # Configuration structures
│   ├── record.go          # DNS record validation
│   ├── duplicates.go      # Duplicate detection
│   ├── templatevar.go     # Template variable handling
│   └── underscores.go     # Underscore validation
├── exitvals/               # Exit value definitions
│   └── exitvalues.go
└── README.md
```

## Domain Connect Specification

Template validation in this project is downstream from the official Domain Connect specification. The authoritative sources are:

### Template Schema
- **URL**: https://raw.githubusercontent.com/Domain-Connect/spec/refs/tags/draft-ietf-dconn-domainconnect-01/template.schema
- **Format**: JSON Schema (Draft 07)
- **Defines**: The complete structure of a Domain Connect template including:
  - Provider and service identifiers (providerId, serviceId)
  - Template metadata (providerName, serviceName, version, logoUrl, description)
  - DNS records (A, AAAA, CNAME, NS, TXT, MX, SPFM, SRV, REDIR301, REDIR302, APEXCNAME)
  - Template variables (values surrounded by %)
  - Security settings (syncBlock, syncRedirectDomain, syncPubKeyDomain, warnPhishing)
  - Multi-instance and shared template support

### Specification Document
- **URL**: https://raw.githubusercontent.com/Domain-Connect/spec/refs/heads/master/Domain%20Connect%20Spec%20Draft.adoc
- **Format**: AsciiDoc
- **Version**: 2.3 (Revision 67)
- **Covers**:
  - DNS Provider discovery via `_domainconnect` TXT records
  - Synchronous flow (immediate DNS changes via web UI)
  - Asynchronous OAuth flow (API-based changes)
  - Template structure and record types
  - Security considerations (signing, phishing warnings)
  - Conflict detection and resolution

## Important Implementation Notes

1. **Template Validation**: The linter validates templates against the JSON schema and performs additional checks like:
   - Duplicate record detection
   - Underscore validation in hostnames
   - Variable syntax validation
   - Logo URL reachability (optional, with `-logos` flag)
   - TTL validation

2. **Exit Codes**: The tool uses bitfield exit codes defined in `exitvals/exitvalues.go`:
   - `CheckOK` (0) - No issues
   - `CheckFatal` (1) - Fatal errors
   - `CheckError` (2) - Errors
   - `CheckWarn` (4) - Warnings
   - `CheckInfo` (8) - Informational messages

3. **Cloudflare Mode**: The `-cloudflare` flag enables Cloudflare-specific template rules.

4. **Pretty Printing**: The `-pretty` and `-inplace` flags can reformat template JSON (note: removes zero-priority MX and SRV fields).

5. **DCTL Error Codes**: Template issue reports use DCTL (Domain Connect Template Linter) codes documented in the project wiki:
   - **Wiki URL**: https://github.com/Domain-Connect/dc-template-linter/wiki/
   - **Example**: https://github.com/Domain-Connect/dc-template-linter/wiki/DCTL1001
   - Each code has a dedicated wiki page explaining the issue and how to resolve it
   - **Adding New Codes**: When introducing new DCTL codes, add them to the wiki repository:
     - **Repository**: `git@github.com:Domain-Connect/dc-template-linter.wiki.git`
     - **Format**: Markdown files (e.g., `DCTL1001.md`)
     - **Content Requirements**:
       - Explain why the issue is reported
       - Provide guidance on how to prevent the issue from appearing

## Related Projects

- **Templates Repository**: https://github.com/Domain-Connect/Templates.git - Public template repository
- **Specification**: https://github.com/Domain-Connect/spec - Official specification
- **Domain Connect Project**: https://www.domainconnect.org

## Testing

Run the linter against templates:
```bash
# Install
go install github.com/Domain-Connect/dc-template-linter@latest

# Validate templates
dc-template-linter ./Templates/*.json

# Check logo URLs
dc-template-linter -logos ./Templates/*.json
```

## Contact

Questions about this tool can be sent to <domain-connect@cloudflare.com>
