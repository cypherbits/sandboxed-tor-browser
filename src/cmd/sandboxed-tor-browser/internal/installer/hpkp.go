// hpkp.go - HPKP key pins.
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

package installer

import (
	"encoding/json"

	"git.schwanenlied.me/yawning/hpkp.git"

	"cmd/sandboxed-tor-browser/internal/data"
)

// StaticHPKPPins is the backing store containing static HPKP pins for
// install/update related hosts.
var StaticHPKPPins *hpkp.MemStorage

func init() {
	StaticHPKPPins = hpkp.NewMemStorage()

	var parsedPins map[string][]string
	if d, err := data.Asset("installer/hpkp.json"); err != nil {
		panic(err)
	} else if err = json.Unmarshal(d, &parsedPins); err != nil {
		panic(err)
	}

	for host, pins := range parsedPins {
		StaticHPKPPins.Add(host, &hpkp.Header{
			Permanent:  true,
			Sha256Pins: pins,
		})
	}
}
