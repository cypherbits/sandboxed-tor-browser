// dialer.go - Tor backed proxy.Dialer.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to bulb, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package bulb

import (
	"strconv"
	"strings"

	"golang.org/x/net/proxy"
)

// SocksPort returns the first configured SOCKS port.
func (c *Conn) SocksPort() (net, addr string, err error) {
	const (
		cmdGetInfo     = "GETINFO"
		socksListeners = "net/listeners/socks"
		unixPrefix     = "unix:"
	)

	// Query for the SOCKS listeners via a GETINFO request.
	resp, err := c.Request("%s %s", cmdGetInfo, socksListeners)
	if err != nil {
		return
	}

	if len(resp.Data) != 1 {
		return "", "", newProtocolError("no SOCKS listeners configured")
	}
	splitResp := strings.Split(resp.Data[0], " ")
	if len(splitResp) < 1 {
		return "", "", newProtocolError("no SOCKS listeners configured")
	}

	// The first listener will have a "net/listeners/socks=" prefix, and all
	// entries are QuotedStrings.
	laddrStr := strings.TrimPrefix(splitResp[0], socksListeners+"=")
	if laddrStr == splitResp[0] {
		return "", "", newProtocolError("failed to parse SOCKS listener")
	}
	laddrStr, _ = strconv.Unquote(laddrStr)

	if strings.HasPrefix(laddrStr, unixPrefix) {
		unixPath := strings.TrimPrefix(laddrStr, unixPrefix)
		return "unix", unixPath, nil
	}
	return "tcp", laddrStr, nil

}

// Dialer returns a proxy.Dialer for the given Tor instance.
func (c *Conn) Dialer(auth *proxy.Auth) (proxy.Dialer, error) {
	net, addr, err := c.SocksPort()
	if err != nil {
		return nil, err
	}

	return proxy.SOCKS5(net, addr, auth, proxy.Direct)
}
