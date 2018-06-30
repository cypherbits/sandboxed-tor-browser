// ldso.go - Dynamic linker routines.
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

package dynlib

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

var errUnsupported = errors.New("dynlib: unsupported os/architecture")

func getLibraries(fn string) ([]string, error) {
	f, err := elf.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return f.ImportedLibraries()
}

// ValidateLibraryClass ensures that the library matches the current
// architecture.
func ValidateLibraryClass(fn string) error {
	f, err := elf.Open(fn)
	if err != nil {
		return err
	}
	defer f.Close()

	var expectedClass elf.Class
	switch runtime.GOARCH {
	case "amd64":
		expectedClass = elf.ELFCLASS64
	default:
		return errUnsupported
	}

	if f.Class != expectedClass {
		return fmt.Errorf("unsupported class: %v: %v", fn, f.Class)
	}
	return nil
}

// FindLdSo returns the path to the `ld.so` dynamic linker for the current
// architecture, which is usually a symlink
func FindLdSo(cache *Cache) (string, string, error) {
	if !IsSupported() {
		return "", "", errUnsupported
	}

	name := ""
	searchPaths := []string{}
	switch runtime.GOARCH {
	case "amd64":
		searchPaths = append(searchPaths, "/lib64")
		name = "ld-linux-x86-64.so.2"
	default:
		panic("dynlib: unsupported architecture: " + runtime.GOARCH)
	}
	searchPaths = append(searchPaths, "/lib")

	for _, d := range searchPaths {
		candidate := filepath.Join(d, name)
		_, err := os.Stat(candidate)
		if err != nil {
			continue
		}

		actual := cache.GetLibraryPath(name)
		if actual == "" {
			continue
		}
		actual, err = filepath.EvalSymlinks(actual)

		return actual, candidate, err
	}

	return "", "", os.ErrNotExist
}

// IsSupported returns true if the architecture/os combination has dynlib
// sypport.
func IsSupported() bool {
	return runtime.GOOS == "linux" && runtime.GOARCH == "amd64"
}
