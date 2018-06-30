//  metadata.go - Tor Browser install/update metadata routines.
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

// Package installer contains routines used for installing and or updating Tor
// Browser.
package installer

import (
	"encoding/json"
	"encoding/xml"
	"fmt"

	"cmd/sandboxed-tor-browser/internal/data"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

type installURLs struct {
	DownloadsURLs   map[string]string
	DownloadsOnions map[string]string
	UpdateURLs      map[string]string
	UpdateOnions    map[string]string
}

var urls *installURLs

type downloads struct {
	Version   string
	Downloads map[string]downloadsArchEntry
}

type downloadsArchEntry map[string]*DownloadsEntry

// DownloadsEntry is a bundle download entry.
type DownloadsEntry struct {
	// Sig is the URL to the PGP signature of the Binary.
	Sig string

	// Binary is the URL to the tar.xz bundle.
	Binary string
}

// DownloadsURL returns the `downloads.json` URL for the configured channel.
func DownloadsURL(cfg *config.Config, useOnion bool) string {
	if useOnion {
		return urls.DownloadsOnions[cfg.Channel]
	}
	return urls.DownloadsURLs[cfg.Channel]
}

// GetDownloadsEntry parses the json file and returns the Version and
// appropriate DownloadsEntry for the current configuration.
func GetDownloadsEntry(cfg *config.Config, b []byte) (string, *DownloadsEntry, error) {
	d := &downloads{}
	if err := json.Unmarshal(b, &d); err != nil {
		return "", nil, err
	}
	if a := d.Downloads[cfg.Architecture]; a == nil {
		return "", nil, fmt.Errorf("no downloads for architecture: %v", cfg.Architecture)
	} else if e := a[cfg.Locale]; e == nil {
		return "", nil, fmt.Errorf("no downloads for locale: %v", cfg.Locale)
	} else {
		return d.Version, e, nil
	}
}

type updates struct {
	XMLName xml.Name       `xml:"updates"`
	Update  []*UpdateEntry `xml:"update"`
}

// UpdateEntry is a MAR update entry.
type UpdateEntry struct {
	Type            string  `xml:"type,attr"`
	DisplayVersion  string  `xml:"displayVersion,attr"`
	AppVersion      string  `xml:"appVersion,attr"`
	PlatformVersion string  `xml:"platformVersion,attr"`
	BuildID         string  `xml:"buildID,attr"`
	DetailsURL      string  `xml:"detailsURL,attr"`
	Actions         string  `xml:"actions,attr"`
	OpenURL         string  `xml:"openURL,attr"`
	Patch           []Patch `xml:"patch"`
}

// Patch is an update patch.
type Patch struct {
	Url          string `xml:"URL,attr"`
	HashFunction string `xml:"hashFunction,attr"`
	HashValue    string `xml:"hashValue,attr"`
	Size         int    `xml:"size,attr"`
	Type         string `xml:"type,attr"`
}

// UpdateURL returns the update check URL for the installed bundle.
func UpdateURL(manif *config.Manifest, useOnion bool) (string, error) {
	base := urls.UpdateURLs[manif.Channel]
	if useOnion {
		base = urls.UpdateOnions[manif.Channel]
	}

	arch := ""
	switch manif.Architecture {
	case "linux64":
		arch = "Linux_x86_64-gcc3"
	case "linux32":
		arch = "Linux_x86-gcc3"
	default:
		return "", fmt.Errorf("unsupported architecture for update: %v", manif.Architecture)
	}
	return fmt.Sprintf("%s/%s/%s/%s", base, arch, manif.Version, manif.Locale), nil
}

// GetUpdateEntry parses the xml file and returns the UpdateEntry if any.
func GetUpdateEntry(b []byte) (*UpdateEntry, error) {
	u := &updates{}
	if err := xml.Unmarshal(b, &u); err != nil {
		return nil, err
	}
	if u.Update == nil {
		return nil, nil
	}

	if len(u.Update) != 1 {
		return nil, fmt.Errorf("more than one update listed in XML file")
	}
	return u.Update[0], nil
}

func init() {
	urls = new(installURLs)
	if b, err := data.Asset("installer/urls.json"); err != nil {
		panic(err)
	} else if err = json.Unmarshal(b, &urls); err != nil {
		panic(err)
	}

}
