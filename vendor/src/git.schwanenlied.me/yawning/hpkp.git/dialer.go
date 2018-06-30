package hpkp

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
)

// Storage is threadsafe hpkp storage interface
type Storage interface {
	Lookup(host string) *Header
	Add(host string, d *Header)
}

// StorageReader is threadsafe hpkp storage interface
type StorageReader interface {
	Lookup(host string) *Header
}

// PinFailureReporter callback function to keep track and report on
// PIN failures
type PinFailureReporter func(p *PinFailure, reportUri string)

// DialerConfig describes how to verify hpkp info and report failures
type DialerConfig struct {
	Storage   StorageReader
	PinOnly   bool
	TLSConfig *tls.Config
	Reporter  PinFailureReporter
	Dial      func(string, string) (net.Conn, error)
}

// NewDialer returns a dialer for making TLS connections with hpkp support
func (c *DialerConfig) NewDialer() func(network, addr string) (net.Conn, error) {
	reporter := c.Reporter
	if reporter == nil {
		reporter = emptyReporter
	}

	return newPinDialer(c.Storage, reporter, c.PinOnly, c.TLSConfig, c.Dial)
}

// emptyReporter does nothing with a pin failure message
var emptyReporter = func(p *PinFailure, reportUri string) {
	return
}

// newPinDialer returns a function suitable for use as DialTLS
func newPinDialer(s StorageReader, r PinFailureReporter, pinOnly bool, defaultTLSConfig *tls.Config, dial func(string, string) (net.Conn, error)) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		dialTLS := func(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
			if dial == nil {
				return tls.Dial(network, addr, cfg)
			}

			if cfg == nil {
				cfg = &tls.Config{}
			} else {
				cfg = cloneTLSConfig(cfg)
			}
			if cfg.ServerName == "" {
				colonPos := strings.LastIndex(addr, ":")
				if colonPos == -1 {
					colonPos = len(addr)
				}
				cfg.ServerName = addr[:colonPos]
			}

			netConn, err := dial(network, addr)
			if err != nil {
				return nil, err
			}
			c := tls.Client(netConn, cfg)
			if err = c.Handshake(); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		}

		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}

		if h := s.Lookup(host); h != nil {
			tlsCfg := &tls.Config{InsecureSkipVerify: pinOnly}
			var c *tls.Conn

			// initial dial
			c, err := dialTLS(network, addr, tlsCfg)
			if err != nil {
				return nil, err
			}

			// intermediates can be pinned as well, loop through leaf-> root looking
			// for pin matches
			validPin := false
			for _, peercert := range c.ConnectionState().PeerCertificates {
				peerPin := Fingerprint(peercert)
				if h.Matches(peerPin) {
					validPin = true
					break
				}
			}
			// was a valid pin found?
			if !validPin {
				// notify failure callback
				r(NewPinFailure(host, port, h, c.ConnectionState()))
				c.Close()
				return nil, errors.New("pin was not valid")
			}
			return c, nil
		}

		// do a normal dial, address isn't in hpkp cache
		return dialTLS(network, addr, defaultTLSConfig)
	}
}
