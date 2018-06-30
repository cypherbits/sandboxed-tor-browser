// utils.go - Misc utility routines.
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

// Package utils provides misc. utility routines.
package utils

import (
	"flag"
	"log"
	"os"
)

const (
	// DirMode is the permissions used when making directories.
	DirMode = os.ModeDir | 0700

	// FileMode is the permissions used when making files.
	FileMode = 0600
)

var enableDebugSpew = false

// DirExists returns true if the path specified exists, and is a directory.
func DirExists(d string) bool {
	if d == "" {
		return false
	}
	fi, err := os.Lstat(d)
	if err != nil {
		return false
	}
	return fi.IsDir()
}

// FileExists returns true if the path specified exists.
func FileExists(f string) bool {
	if _, err := os.Lstat(f); err != nil && os.IsNotExist(err) {
		// This might be an EPERM, but bubblewrap can have elevated privs,
		// so this may succeed.  If it doesn't, the error will be caught
		// later.
		return false
	}
	return true
}

// Debugf logs at the debug level.
func Debugf(format string, v ...interface{}) {
	if enableDebugSpew {
		log.Printf(format, v...)
	}
}

func init() {
	flag.BoolVar(&enableDebugSpew, "debug", false, "Enable debug logging.")
}
