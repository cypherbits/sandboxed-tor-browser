// cache.go - Dynamic linker cache routines.
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

// Package dynlib provides routines for interacting with the glibc ld.so dynamic
// linker/loader.
package dynlib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"sort"

	. "cmd/sandboxed-tor-browser/internal/utils"
)

const (
	ldSoCache = "/etc/ld.so.cache"

	flagX8664Lib64 = 0x0300
	flagElf        = 1
	flagElfLibc6   = 3
)

// FilterFunc is a function that implements a filter to allow rejecting
// dependencies when resolving libraries.
type FilterFunc func(string) error

// Quoting from sysdeps/generic/dl-cache.h:
//
// libc5 and glibc 2.0/2.1 use the same format.  For glibc 2.2 another
// format has been added in a compatible way:
// The beginning of the string table is used for the new table:
//   old_magic
//   nlibs
//   libs[0]
//   ...
//   libs[nlibs-1]
//   pad, new magic needs to be aligned
//	     - this is string[0] for the old format
//   new magic - this is string[0] for the new format
//   newnlibs
//   ...
//   newlibs[0]
//   ...
//   newlibs[newnlibs-1]
//   string 1
//   string 2
//   ...

// Cache is a representation of the `ld.so.cache` file.
type Cache struct {
	store map[string]cacheEntries
}

// GetLibraryPath returns the path to the given library, if any.  This routine
// makes no attempt to disambiguate multiple libraries (eg: via hwcap/search
// path).
func (c *Cache) GetLibraryPath(name string) string {
	ents, ok := c.store[name]
	if !ok {
		return ""
	}

	return ents[0].value
}

// ResolveLibraries returns a map of library paths and their aliases for a
// given set of binaries, based off the ld.so.cache, libraries known to be
// internal, and a search path.
func (c *Cache) ResolveLibraries(binaries []string, extraLibs []string, ldLibraryPath, fallbackSearchPath string, filterFn FilterFunc) (map[string][]string, error) {
	searchPaths := filepath.SplitList(ldLibraryPath)
	fallbackSearchPaths := filepath.SplitList(fallbackSearchPath)
	libraries := make(map[string]string)

	// Breadth-first iteration of all the binaries, and their dependencies.
	checkedFile := make(map[string]bool)
	checkedLib := make(map[string]bool)
	toCheck := binaries
	for {
		newToCheck := make(map[string]bool)
		if len(toCheck) == 0 {
			break
		}
		for _, fn := range toCheck {
			if filterFn != nil {
				if err := filterFn(fn); err != nil {
					Debugf("dynlib error filterFn: %v", err)
					return nil, err
				}
			}

			impLibs, err := getLibraries(fn)
			if err != nil {
				Debugf("dynlib error getLibraries: %v", err)
				return nil, err
			}
			Debugf("dynlib: %v imports: %v", fn, impLibs)
			checkedFile[fn] = true

			// The internal libraries also need recursive resolution,
			// so just append them to the first binary.
			if extraLibs != nil {
				Debugf("dynlib: Appending extra libs: %v", extraLibs)
				impLibs = append(impLibs, extraLibs...)
				extraLibs = nil
			}

			for _, lib := range impLibs {
				if checkedLib[lib] {
					continue
				}

				isInPath := func(l string, p []string) string {
					for _, d := range p {
						maybePath := filepath.Join(d, l)
						if FileExists(maybePath) {
							return maybePath
						}
					}
					return ""
				}

				// Look for the library in the various places.
				var libPath string
				var inLdLibraryPath, inCache, inFallbackPath bool
				if libPath = isInPath(lib, searchPaths); libPath != "" {
					inLdLibraryPath = true
				} else if libPath = c.GetLibraryPath(lib); libPath != "" {
					inCache = true
				} else if libPath = isInPath(lib, fallbackSearchPaths); libPath != "" {
					inFallbackPath = true
				} else {
					return nil, fmt.Errorf("dynlib: Failed to find library: %v", lib)
				}

				var libSrc string
				switch {
				case inLdLibraryPath:
					libSrc = "LD_LIBRARY_PATH"
				case inCache:
					libSrc = "ld.so.conf"
				case inFallbackPath:
					libSrc = "Filesystem"
				}
				Debugf("dynlib: Found %v (%v).", lib, libSrc)

				// Register the library, assuming it's not in what will
				// presumably be `LD_LIBRARY_PATH` inside the hugbox.
				if !inLdLibraryPath {
					libraries[lib] = libPath
				}
				checkedLib[lib] = true

				if !checkedFile[libPath] {
					newToCheck[libPath] = true
				}
			}
		}
		toCheck = []string{}
		for k, _ := range newToCheck {
			toCheck = append(toCheck, k)
		}
	}

	// De-dup the libraries map by figuring out what can be symlinked.
	ret := make(map[string][]string)
	for lib, fn := range libraries {
		f, err := filepath.EvalSymlinks(fn)
		if err != nil {
			return nil, err
		}

		vec := ret[f]
		vec = append(vec, lib)
		ret[f] = vec
	}

	// XXX: This should sanity check to ensure that aliases are distinct.

	return ret, nil
}

type cacheEntry struct {
	key, value string
	flags      uint32
	osVersion  uint32
	hwcap      uint64
}

type cacheEntries []*cacheEntry

func (e cacheEntries) Len() int {
	return len(e)
}

func (e cacheEntries) Less(i, j int) bool {
	// Bigger hwcap should come first.
	if e[i].hwcap > e[j].hwcap {
		return true
	}
	// Bigger osVersion should come first.
	if e[i].osVersion > e[j].osVersion {
		return true
	}

	// Preserve the ordering otherwise.
	return i < j
}

func (e cacheEntries) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

func getNewLdCache(b []byte) ([]byte, int, error) {
	const entrySz = 4 + 4 + 4

	// The new format is embedded in the old format, so do some light
	// parsing/validation to get to the new format's header.
	cacheMagic := []byte{
		'l', 'd', '.', 's', 'o', '-', '1', '.', '7', '.', '0', 0,
	}

	// old_magic
	if !bytes.HasPrefix(b, cacheMagic) {
		return nil, 0, fmt.Errorf("dynlib: ld.so.cache has invalid old_magic")
	}
	off := len(cacheMagic)
	b = b[off:]

	// nlibs
	if len(b) < 4 {
		return nil, 0, fmt.Errorf("dynlib: ld.so.cache truncated (nlibs)")
	}
	nlibs := int(binary.LittleEndian.Uint32(b))
	off += 4
	b = b[4:]

	// libs[nlibs]
	nSkip := entrySz * nlibs
	if len(b) < nSkip {
		return nil, 0, fmt.Errorf("dynlib: ld.so.cache truncated (libs[])")
	}
	off += nSkip
	b = b[nSkip:]

	// new_magic is 8 byte aligned.
	padLen := (((off+8-1)/8)*8 - off)
	if len(b) < padLen {
		return nil, 0, fmt.Errorf("dynlib: ld.so.cache truncated (pad)")
	}
	return b[padLen:], nlibs, nil
}

// LoadCache loads and parses the `ld.so.cache` file.
//
// See `sysdeps/generic/dl-cache.h` in the glibc source tree for details
// regarding the format.
func LoadCache() (*Cache, error) {
	const entrySz = 4 + 4 + 4 + 4 + 8

	if !IsSupported() {
		return nil, errUnsupported
	}

	ourOsVersion := getOsVersion()
	Debugf("dynlib: osVersion: %08x", ourOsVersion)

	c := new(Cache)
	c.store = make(map[string]cacheEntries)

	b, err := ioutil.ReadFile(ldSoCache)
	if err != nil {
		return nil, err
	}

	// It is likely safe to assume that everyone is running glibc >= 2.2 at
	// this point, so extract the "new format" from the "old format".
	b, _, err = getNewLdCache(b)
	if err != nil {
		return nil, err
	}
	stringTable := b

	// new_magic.
	//glibc-ld.so.cache1.1
	cacheMagicNew := []byte{
		'g', 'l', 'i', 'b', 'c', '-', 'l', 'd', '.', 's', 'o', '.', 'c', 'a', 'c',
		'h', 'e', '1', '.', '1',
	}
	if !bytes.HasPrefix(b, cacheMagicNew) {
		return nil, fmt.Errorf("dynlib: ld.so.cache has invalid new_magic")
	}
	b = b[len(cacheMagicNew):]

	// nlibs, len_strings, unused[].
	if len(b) < 2*4+5*4 {
		return nil, fmt.Errorf("dynlib: ld.so.cache truncated (new header)")
	}
	nlibs := int(binary.LittleEndian.Uint32(b))
	b = b[4:]
	lenStrings := int(binary.LittleEndian.Uint32(b))
	b = b[4+20:] // Also skip unused[].
	rawLibs := b[:nlibs*entrySz]
	b = b[len(rawLibs):]
	if len(b) != lenStrings {
		return nil, fmt.Errorf("dynlib: lenStrings appears invalid")
	}

	getString := func(idx int) (string, error) {
		if idx < 0 || idx > len(stringTable) {
			return "", fmt.Errorf("dynlib: string table index out of bounds")
		}
		l := bytes.IndexByte(stringTable[idx:], 0)
		if l == 0 {
			return "", nil
		}
		return string(stringTable[idx : idx+l]), nil
	}

	// libs[]
	var flagCheckFn func(uint32) bool
	switch runtime.GOARCH {
	case "amd64":
		flagCheckFn = func(flags uint32) bool {
			const wantFlags = flagX8664Lib64 | flagElfLibc6
			return flags&wantFlags == wantFlags
		}
		// HWCAP is unused on amd64.
	default:
		panic(errUnsupported)
	}

	for i := 0; i < nlibs; i++ {
		rawE := rawLibs[entrySz*i : entrySz*(i+1)]

		e := new(cacheEntry)
		e.flags = binary.LittleEndian.Uint32(rawE[0:])
		kIdx := int(binary.LittleEndian.Uint32(rawE[4:]))
		vIdx := int(binary.LittleEndian.Uint32(rawE[8:]))
		e.osVersion = binary.LittleEndian.Uint32(rawE[12:])
		e.hwcap = binary.LittleEndian.Uint64(rawE[16:])

		e.key, err = getString(kIdx)
		if err != nil {
			return nil, fmt.Errorf("dynlib: failed to query key: %v", err)
		}
		e.value, err = getString(vIdx)
		if err != nil {
			return nil, fmt.Errorf("dynlib: failed to query value: %v", err)
		}

		// Discard libraries we have no hope of using, either due to
		// osVersion, or hwcap.
		if ourOsVersion < e.osVersion {
			Debugf("dynlib: ignoring library: %v (osVersion: %x)", e.key, e.osVersion)
		} else if err = ValidateLibraryClass(e.value); err != nil {
			Debugf("dynlib: ignoring library %v (%v)", e.key, err)
		} else if flagCheckFn(e.flags) {
			vec := c.store[e.key]
			vec = append(vec, e)
			c.store[e.key] = vec
		} else {
			Debugf("dynlib: ignoring library: %v (flags: %x, hwcap: %x)", e.key, e.flags, e.hwcap)
		}
	}

	for lib, entries := range c.store {
		if len(entries) == 1 {
			continue
		}

		// Sort the entires in order of prefernce similar to what ld-linux.so
		// will do.
		sort.Sort(entries)
		c.store[lib] = entries

		paths := []string{}
		for _, e := range entries {
			paths = append(paths, e.value)
		}

		Debugf("dynlib: debug: Multiple entry: %v: %v", lib, paths)
	}

	return c, nil
}
