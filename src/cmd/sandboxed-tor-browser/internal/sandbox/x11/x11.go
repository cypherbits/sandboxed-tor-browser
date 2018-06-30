// x11.go - X11 related sandbox routines.
// Copyright (C) 2016, 2017  Yawning Angel.
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

// Package x11 contains the X11 sandbox surrogate and other X11 related
// sandboxing routines.
package x11

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	. "cmd/sandboxed-tor-browser/internal/utils"
)

const SockDir = "/tmp/.X11-unix"

func craftAuthority(hugboxHostname, realDisplay string) ([]byte, error) {
	const familyAFLocal = 256

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	// Read in the real Xauthority file.
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	xauthPath := os.Getenv("XAUTHORITY")
	if xauthPath == "" {
		xauthPath = filepath.Join(u.HomeDir, ".Xauthority")
	} else if strings.HasPrefix(xauthPath, "~/") {
		xauthPath = filepath.Join(u.HomeDir, xauthPath[1:])
	}
	real, err := ioutil.ReadFile(xauthPath)
	if err != nil {
		return nil, err
	}

	extractXString := func(s []byte) ([]byte, error) {
		// uint16_t sLen
		if len(s) < 2 {
			return nil, fmt.Errorf("truncated input buffer (length)")
		}
		sLen := binary.BigEndian.Uint16(s[0:])

		// uint8_t s[sLen]
		if len(s[2:]) < int(sLen) {
			return nil, fmt.Errorf("truncated input buffer (string) %v %v", len(s[2:]), sLen)
		}
		return s[2 : 2+sLen], nil
	}

	encodeXString := func(s []byte) []byte {
		x := make([]byte, 2, 2+len(s))
		binary.BigEndian.PutUint16(x[0:], uint16(len(s)))
		x = append(x, s...)
		return x
	}

	// Parse the Xauthority to extract the cookie.
	for len(real) > 0 {
		// The format is just the following record concattenated repeatedly,
		// all integers Big Endian:
		//
		//  uint16_t family (0: IPv4, 6: IPv6, 256: AF_LOCAL)
		//
		//  uint16_t addr_len
		//  uint8_t  addr[addr_len]
		//
		//  uint16_t disp_len
		//  uint8_t  disp[disp_len]
		//
		//  uint16_t auth_meth_len
		//  uint8_t auth_meth[auth_meth_len]
		//
		//  uint16_t auth_data_len
		//  uint8_t  auth_data[auth_data_len]

		idx := 0

		if len(real) < 2 {
			break
		}
		family := binary.BigEndian.Uint16(real[idx:])
		idx += 2

		addr, err := extractXString(real[idx:])
		if err != nil {
			return nil, err
		}
		idx += 2 + len(addr)

		disp, err := extractXString(real[idx:])
		if err != nil {
			return nil, err
		}
		idx += 2 + len(disp)

		authMeth, err := extractXString(real[idx:])
		if err != nil {
			return nil, err
		}
		idx += 2 + len(authMeth)

		authData, err := extractXString(real[idx:])
		if err != nil {
			return nil, err
		}
		idx += 2 + len(authData)

		real = real[idx:]

		// Figure out of this is the relevant entry, and craft the entry to
		// be used in the sandbox.
		if family != familyAFLocal {
			continue
		}
		if string(addr) != hostname {
			continue
		}
		if string(disp) != realDisplay {
			continue
		}

		// Hostname rewritten to the sandboxed one.  The display is always
		// display `:0`.
		xauth := make([]byte, 2)
		binary.BigEndian.PutUint16(xauth[0:], family)
		if hugboxHostname == "" {
			xauth = append(xauth, encodeXString([]byte(hostname))...)
		} else {
			xauth = append(xauth, encodeXString([]byte(hugboxHostname))...)
		}
		xauth = append(xauth, encodeXString([]byte("0"))...)
		xauth = append(xauth, encodeXString(authMeth)...)
		xauth = append(xauth, encodeXString(authData)...)
		return xauth, nil
	}

	return nil, fmt.Errorf("failed to find an appropriate Xauthority entry")
}

type SandboxedX11 struct {
	hSock, pSock string
	hDisplay     string

	Display    string
	Xauthority []byte

	Surrogate *Surrogate
	launched  bool
}

func (x *SandboxedX11) Socket() string {
	if !x.launched {
		panic("BUG: Socket() called prior to LaunchSurrogate")
	}
	if x.Surrogate != nil {
		return x.Surrogate.pSock
	}
	return x.hSock
}

func (x *SandboxedX11) LaunchSurrogate() error {
	// Launch the surrogate unless disabled.
	Debugf("sandbox: X11: Launching surrogate")

	var err error
	if x.Surrogate, err = launchSurrogate(x.hSock, x.pSock, x.hDisplay); err != nil {
		return err
	}
	x.launched = true
	return nil
}

func New(display, hostname, pSock string) (*SandboxedX11, error) {
	// Apply override, and determine the display.
	for _, d := range []string{display, os.Getenv("DISPLAY")} {
		if d != "" {
			display = d
			break
		}
	}
	if display == "" {
		return nil, fmt.Errorf("sandbox: no DISPLAY env var set")
	}
	if !strings.HasPrefix(display, ":") {
		return nil, fmt.Errorf("sandbox: non-local X11 displays not supported")
	}

	// Certain multimonitor setups use the form ":0.0" or similar.
	var d []byte
	for _, c := range []byte(strings.TrimLeft(display, ":")) {
		if c < 0x30 || c > 0x39 {
			break
		}
		d = append(d, c)
	}
	displayNum := string(d)
	if len(displayNum) == 0 {
		return nil, fmt.Errorf("sandbox: failed to determine X11 display")
	}

	// Store the various sandboxed X11 parameters.
	x := new(SandboxedX11)
	x.Display = ":0"
	x.hDisplay = display
	x.hSock = filepath.Join(SockDir, "X"+displayNum)
	x.pSock = pSock

	var err error
	if x.Xauthority, err = craftAuthority(hostname, displayNum); err != nil {
		// Some systems don't have an Xauthority file, like my Fedora VM.
		Debugf("sandbox: Xauthority: %v", err)
	}

	return x, nil
}
