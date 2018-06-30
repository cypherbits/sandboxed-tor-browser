// client.go - SOCSK5 client implementation.
// Copyright (C) 2015, 2016  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package socks5

import (
	"net"

	"golang.org/x/net/proxy"
)

// Redispatch dials the provided proxy and redispatches an existing request.
func Redispatch(proxyNet, proxyAddr string, req *Request) (net.Conn, error) {
	if req.Cmd != CommandConnect {
		return nil, clientError(ReplyCommandNotSupported)
	}

	var auth *proxy.Auth
	if req.Auth.Uname != nil {
		auth = &proxy.Auth{
			User:     string(req.Auth.Uname),
			Password: string(req.Auth.Passwd),
		}
	}
	d, err := proxy.SOCKS5(proxyNet, proxyAddr, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}

	return d.Dial("tcp", req.Addr.String())
}
