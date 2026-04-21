package libdctlint

import (
	"github.com/Domain-Connect/dc-template-linter/internal"
	"github.com/rs/zerolog"
)

// DCTLMessage holds a captured linting message produced during a library-mode
// template check. Code is the DCTL code that triggered the message, Level is
// its zerolog severity, and Message is the JSON-encoded zerolog event string.
type DCTLMessage struct {
	Code    internal.DCTL
	Level   zerolog.Level
	Message string
}

// Conf holds template checking instructions. The field type FileName must
// be updated each time CheckTemplate() is called to match with the
// bufio.Reader argument.
type Conf struct {
	fileName    string
	tlog        zerolog.Logger
	toleration  zerolog.Level
	collision   map[string]bool
	duplicates  map[uint64]bool
	checkLogos  bool
	mergeOrFail bool
	cloudflare  bool
	inplace     bool
	increment   bool
	prettyPrint bool
	ttl         uint32
	indent      uint
	lib         bool
	messages    []DCTLMessage
	sharedvar   string
}

// NewConf will create template check configuration.
func NewConf() *Conf {
	return &Conf{
		collision: make(map[string]bool),
	}
}

func (c *Conf) SetFilename(fn string) *Conf {
	c.fileName = fn
	return c
}

func (c *Conf) SetLogger(l zerolog.Logger) *Conf {
	c.tlog = l
	return c
}

func (c *Conf) SetToleration(s string) *Conf {
	t := zerolog.DebugLevel
	switch s {
	case "any":
		t = zerolog.Disabled
	case "error":
		t = zerolog.ErrorLevel
	case "warn":
		t = zerolog.WarnLevel
	case "info":
		t = zerolog.InfoLevel
	case "debug":
		t = zerolog.DebugLevel
	}
	c.toleration = t
	return c
}

func (c *Conf) GetToleration() zerolog.Level {
	return c.toleration
}

func (c *Conf) SetCheckLogos(b bool) *Conf {
	c.checkLogos = b
	return c
}

func (c *Conf) SetMergeOrFail(b bool) *Conf {
	c.mergeOrFail = b
	return c
}

func (c *Conf) SetCloudflare(b bool) *Conf {
	c.cloudflare = b
	return c
}

func (c *Conf) SetInplace(b bool) *Conf {
	c.inplace = b
	return c
}

func (c *Conf) SetIndent(i uint) *Conf {
	c.indent = i
	return c
}

func (c *Conf) SetIncrement(b bool) *Conf {
	c.increment = b
	return c
}

func (c *Conf) SetPrettyPrint(b bool) *Conf {
	c.prettyPrint = b
	return c
}

func (c *Conf) SetTTL(t uint32) *Conf {
	c.ttl = t
	return c
}

// SetLib enables or disables library mode. When enabled, CheckTemplate()
// captures DCTL messages to an internal list instead of writing to the
// zerolog global logger. Captured messages are accessible via GetMessages().
func (c *Conf) SetLib(b bool) *Conf {
	c.lib = b
	return c
}

// GetMessages returns the list of DCTL messages captured during the most
// recent CheckTemplate() call when library mode is active (SetLib(true)).
// The slice is reset at the start of each CheckTemplate() call.
func (c *Conf) GetMessages() []DCTLMessage {
	return c.messages
}
