// pulse.go - PulseAudio related sandbox routines.
// Copyright (C) 2016  Yawning Angel.
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

package sandbox

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	xdg "github.com/cep21/xdgbasedir"

	"cmd/sandboxed-tor-browser/internal/dynlib"
	. "cmd/sandboxed-tor-browser/internal/utils"
)

func (h *hugbox) enablePulseAudio() error {
	const (
		pulseServer = "PULSE_SERVER"
		pulseCookie = "PULSE_COOKIE"
		unixPrefix  = "unix:"
	)

	// TODO: PulseAudio can optionally store information regarding the location
	// of the socket and the cookie contents as X11 root window properties.

	// The config may be in a pair of enviornment variables, so check those
	// along with the modern default locations.
	sockPath := os.Getenv(pulseServer)
	if sockPath == "" {
		hostRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if hostRuntimeDir == "" {
			// Should never happen, the app requires/uses XDG_RUNTIME_DIR.
			return fmt.Errorf("hugbox: BUG: Couldn't determine XDG_RUNTIME_DIR")
		}
		sockPath = filepath.Join(hostRuntimeDir, "pulse", "native")
	} else if strings.HasPrefix(sockPath, unixPrefix) {
		sockPath = strings.TrimPrefix(sockPath, unixPrefix)
	} else {
		return fmt.Errorf("sandbox: non-local PulseAudio not supported")
	}

	if fi, err := os.Stat(sockPath); err != nil {
		// No PulseAudio socket.
		return fmt.Errorf("sandbox: no PulseAudio socket")
	} else if fi.Mode()&os.ModeSocket == 0 {
		// Not an AF_LOCAL socket.
		return fmt.Errorf("sandbox: PulseAudio socket isn't an AF_LOCAL socket")
	}

	// Read in the cookie, if any.
	var err error
	var cookie []byte
	cookiePath := os.Getenv(pulseCookie)
	if cookiePath == "" {
		cookiePath, err = xdg.GetConfigFileLocation("pulse/cookie")
		if err != nil {
			// No cookie found, auth is probably disabled.
			cookiePath = ""
		}
	}
	if cookiePath != "" {
		cookie, err = ioutil.ReadFile(cookiePath)
		if err != nil {
			return err
		}
	}

	// Setup access to PulseAudio in the sandbox:
	//  * The socket.
	//  * The cookie, if any.
	//  * A `client.conf` that disables shared memory.
	sandboxPulseSock := filepath.Join(h.runtimeDir, "pulse", "native")
	sandboxPulseConf := filepath.Join(h.runtimeDir, "pulse", "client.conf")

	h.bind(sockPath, sandboxPulseSock, false)
	h.setenv(pulseServer, "unix:"+sandboxPulseSock)
	h.setenv("PULSE_CLIENTCONFIG", sandboxPulseConf)
	h.file(sandboxPulseConf, []byte("enable-shm=no"))

	if cookie != nil {
		sandboxPulseCookie := filepath.Join(h.runtimeDir, "pulse", "cookie")
		h.file(sandboxPulseCookie, cookie)
		h.setenv(pulseCookie, sandboxPulseCookie)
	}

	return nil
}

func (h *hugbox) appendRestrictedPulseAudio(cache *dynlib.Cache) ([]string, string, string, error) {
	const libPulse = "libpulse.so.0"

	extraLibs := []string{}
	ldLibraryPath := ""
	extraLdLibraryPath := ""

	paLibsPath := findDistributionDependentDir(nil, "", "pulseaudio")
	if paLibsPath != "" && cache.GetLibraryPath(libPulse) != "" {
		const restrictedPulseDir = "/usr/lib/pulseaudio"

		// The library search path ("/usr/lib/pulseaudio"), is
		// hardcoded into libpulse.so.0, because you suck, and we hate
		// you.

		extraLibs = append(extraLibs, libPulse)
		h.dir(restrictedPulseDir)
		ldLibraryPath = ldLibraryPath + ":" + paLibsPath
		extraLdLibraryPath = extraLdLibraryPath + ":" + restrictedPulseDir

		matches, err := filepath.Glob(paLibsPath + "/*.so")
		if err != nil {
			return nil, "", "", err
		}
		for _, v := range matches {
			if dynlib.ValidateLibraryClass(v) != nil {
				Debugf("sandbox: Unsuitable PulseAudio so: %v", v)
				continue
			}
			_, f := filepath.Split(v)
			if strings.HasPrefix(f, "libpulsecore") {
				Debugf("sandbox: Skipping libpulsecore: %v", v)
				continue
			}
			h.roBind(v, filepath.Join(restrictedPulseDir, f), false)
			extraLibs = append(extraLibs, f)
		}

		return extraLibs, ldLibraryPath, extraLdLibraryPath, nil
	}

	return nil, "", "", fmt.Errorf("failed to find PulseAudio libraries")
}
