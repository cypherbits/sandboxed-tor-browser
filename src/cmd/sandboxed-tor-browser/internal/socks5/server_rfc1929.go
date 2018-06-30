// server_rfc1929.go - SOCSK 5 server authentication.
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
	"fmt"
	"io"
)

const (
	authRFC1929Ver     = 0x01
	authRFC1929Success = 0x00
	authRFC1929Fail    = 0x01
)

// AuthInfo is the RFC 1929 Username/Password authentication data.
type AuthInfo struct {
	Uname  []byte
	Passwd []byte
}

func (req *Request) authRFC1929() (err error) {
	sendErrResp := func() {
		// Swallow write/flush errors, the auth failure is the relevant error.
		resp := []byte{authRFC1929Ver, authRFC1929Fail}
		req.conn.Write(resp[:])
	}

	// The client sends a Username/Password request.
	//  uint8_t ver (0x01)
	//  uint8_t ulen (>= 1)
	//  uint8_t uname[ulen]
	//  uint8_t plen (>= 1)
	//  uint8_t passwd[plen]

	if err = req.readByteVerify("auth version", authRFC1929Ver); err != nil {
		sendErrResp()
		return
	}

	// Read the username.
	var ulen byte
	if ulen, err = req.readByte(); err != nil {
		sendErrResp()
		return
	} else if ulen < 1 {
		sendErrResp()
		return fmt.Errorf("username with 0 length")
	}
	uname := make([]byte, ulen)
	if _, err = io.ReadFull(req.conn, uname); err != nil {
		sendErrResp()
		return
	}

	// Read the password.
	var plen byte
	if plen, err = req.readByte(); err != nil {
		sendErrResp()
		return
	} else if plen < 1 {
		sendErrResp()
		return fmt.Errorf("password with 0 length")
	}
	passwd := make([]byte, plen)
	if _, err = io.ReadFull(req.conn, passwd); err != nil {
		sendErrResp()
		return
	}

	req.Auth.Uname = uname
	req.Auth.Passwd = passwd

	resp := []byte{authRFC1929Ver, authRFC1929Success}
	_, err = req.conn.Write(resp[:])
	return
}
