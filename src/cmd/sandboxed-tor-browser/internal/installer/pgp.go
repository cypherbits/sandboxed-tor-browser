// keyring.go - Tor Browser Bundle PGP key.
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
	"bytes"
	"fmt"
	"time"

	"golang.org/x/crypto/openpgp"

	"cmd/sandboxed-tor-browser/internal/data"
)

const (
	tbbSigningKeyID    = 0xEB774491D9FF06E2
	tbbSigningKeyAsset = "installer/0x4E2C6E8793298290.asc"
)

var tbbKeyRing openpgp.KeyRing
var tbbPgpKey *openpgp.Entity

// ValidatePGPSignature validates the bundle and signature pair against the TBB
// key ring.
func ValidatePGPSignature(bundle, signature []byte) error {
	if ent, err := openpgp.CheckArmoredDetachedSignature(tbbKeyRing, bytes.NewReader(bundle), bytes.NewReader(signature)); err != nil {
		return err
	} else if ent != tbbPgpKey {
		return fmt.Errorf("unknown entity signed bundle")
	}
	return nil
}

func initDISABLED() {
	var err error

	pem, err := data.Asset(tbbSigningKeyAsset)
	if err != nil {
		panic(err)
	}

	// Decode the hardcoded PGP key.
	buf := bytes.NewReader(pem)
	tbbKeyRing, err = openpgp.ReadArmoredKeyRing(buf)
	if err != nil {
		panic(err)
	}

	// Pull out the TBB key for easy access.
	keys := tbbKeyRing.KeysById(tbbSigningKeyID)
	if len(keys) != 1 {
		panic("more than 1 key in hard coded key ring")
	}
	tbbPgpKey = keys[0].Entity

	// Ensure that at least one subkey hasn't expired.
	sigValid := false
	for _, subKey := range tbbPgpKey.Subkeys {
		sigValid = sigValid || !subKey.Sig.KeyExpired(time.Now())
	}
	if !sigValid {
		panic("tbb PGP subkeys all expired")
	}
}
