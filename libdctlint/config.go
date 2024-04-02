package libdctlint

import (
	"github.com/rs/zerolog"
)

// Conf holds template checking instructions. The field type FileName must
// be updated each time CheckTemplate() is called to match with the
// bufio.Reader argument.
type Conf struct {
	fileName    string
	tlog        zerolog.Logger
	collision   map[string]bool
	checkLogos  bool
	cloudflare  bool
	inplace     bool
	increment   bool
	prettyPrint bool
	ttl         uint
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

func (c *Conf) SetCheckLogos(b bool) *Conf {
	c.checkLogos = b
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

func (c *Conf) SetIncrement(b bool) *Conf {
	c.increment = b
	return c
}

func (c *Conf) SetPrettyPrint(b bool) *Conf {
	c.prettyPrint = b
	return c
}

func (c *Conf) SetTTL(t uint) *Conf {
	c.ttl = t
	return c
}
