// Go 1.8 and later tls.Config deep copy.

// +build go1.8

package hpkp

import (
	"crypto/tls"
)

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	return cfg.Clone()
}
