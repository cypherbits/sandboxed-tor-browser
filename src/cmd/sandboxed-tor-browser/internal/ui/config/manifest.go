// manifest.go - Manifest routines.
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

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cmd/sandboxed-tor-browser/internal/utils"
)

// Manifest contains the installed Tor Browser information.
type Manifest struct {
	// Version is the installed version.
	Version string `json:"version,omitEmpty"`

	// Architecture is the installed Tor Browser architecture.
	Architecture string `json:"architecture,omitEmpty"`

	// Channel is the installed Tor Browser channel.
	Channel string `json:"channel,omitEmpty"`

	// Locale is the installed Tor Browser locale.
	Locale string `json:"locale,omitEmpty"`

	isDirty bool
	path    string
}

// SetVersion sets the manifest version and marks the config dirty.
func (m *Manifest) SetVersion(v string) {
	if m.Version != v {
		m.isDirty = true
		m.Version = v
	}
}

// Sync flushes the manifest to disk, if the manifest is dirty.
func (m *Manifest) Sync() error {
	if m.isDirty {
		// Encode to JSON and write to disk.
		if b, err := json.Marshal(&m); err != nil {
			return err
		} else if err = ioutil.WriteFile(m.path, b, utils.FileMode); err != nil {
			return err
		}

		m.isDirty = false
	}
	return nil
}

// BundleVersionAtLeast returns true if the bundle version is greater than or
// equal to the specified version.
func (m *Manifest) BundleVersionAtLeast(vStr string) bool {
	cmp, err := bundleVersionCompare(m.Version, vStr)
	if err != nil {
		return false
	}
	return cmp >= 0
}

// BundleUpdateVersionValid returns true if the proposed update version is
// actually an update.
func (m *Manifest) BundleUpdateVersionValid(vStr string) bool {
	cmp, err := bundleVersionCompare(m.Version, vStr)
	if err != nil {
		return false
	}
	return cmp < 0
}

func bundleVersionParse(vStr string) (*[4]int, bool, error) {
	vStr = strings.TrimSuffix(vStr, "-hardened")
	vStr = strings.Replace(vStr, "a", ".0.", 1)

	var out [4]int
	vSplit := strings.Split(vStr, ".")
	isAlpha := len(vSplit) == 4

	for idx, s := range strings.Split(vStr, ".") {
		i, err := strconv.Atoi(s)
		if err != nil {
			return nil, false, err
		}
		out[idx] = i
	}
	out[3] = -out[3]

	return &out, isAlpha, nil
}

func bundleVersionCompare(a, b string) (int, error) {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))

	if a == b {
		return 0, nil // Equal.
	}

	aVer, aAlpha, err := bundleVersionParse(a)
	if err != nil {
		return 0, err
	}
	bVer, bAlpha, err := bundleVersionParse(b)
	if err != nil {
		return 0, err
	}

	for i := 0; i < 3; i++ {
		if aVer[i] > bVer[i] {
			return 1, nil
		}
		if aVer[i] < bVer[i] {
			return -1, nil
		}
	}

	if aAlpha && !bAlpha { // Alpha vs Release.
		return -1, nil
	}
	if !aAlpha && bAlpha { // Release vs Alpha.
		return 1, nil
	}

	// Alpha vs Alpha.
	aVer[3], bVer[3] = -aVer[3], -bVer[3]
	if aVer[3] < bVer[3] {
		return -1, nil
	}
	if bVer[3] < aVer[3] {
		return 1, nil
	}

	return 0, nil // One is probably hardened, the other isn't.
}

// Purge deletes the manifest.
func (m *Manifest) Purge() {
	os.Remove(m.path)
}

// LoadManifest loads a manifest if present.  Note that a missing manifest is
// not treated as an error.
func LoadManifest(cfg *Config) (*Manifest, error) {
	m := new(Manifest)

	// Somewhere in the 0.0.1-dev era, the location for the manifiest file
	// changed.  Transition gracefully by moving the file to the new location.
	oldManifestPath := filepath.Join(cfg.ConfigDir, manifestFile)
	if _, err := os.Lstat(oldManifestPath); err == nil {
		if err = os.Rename(oldManifestPath, cfg.manifestPath); err != nil {
			return nil, fmt.Errorf("failed to move manifest to new location: %v", err)
		}
	}

	// Load the manifest file.
	if b, err := ioutil.ReadFile(cfg.manifestPath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	} else if err = json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m.path = cfg.manifestPath
	return m, nil
}

// NewManifest returns a new manifest.
func NewManifest(cfg *Config, version string) *Manifest {
	m := new(Manifest)
	m.Version = version
	m.Architecture = cfg.Architecture
	m.Channel = cfg.Channel
	m.Locale = cfg.Locale

	m.isDirty = true
	m.path = cfg.manifestPath

	return m
}
