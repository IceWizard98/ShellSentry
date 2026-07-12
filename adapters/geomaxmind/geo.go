package geomaxmind

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

type Geo struct{ reader *geoip2.Reader }

func New(dbPath string) (*Geo, error) {
	r, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open geoip db: %w", err)
	}
	return &Geo{reader: r}, nil
}

// Country returns the ISO country code, or "" for an unparseable/unknown IP.
func (g *Geo) Country(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", nil
	}
	if g.reader == nil {
		return "", nil
	}
	rec, err := g.reader.Country(parsed)
	if err != nil {
		return "", fmt.Errorf("geo lookup: %w", err)
	}
	return rec.Country.IsoCode, nil
}

func (g *Geo) Close() error {
	if g.reader != nil {
		return g.reader.Close()
	}
	return nil
}
