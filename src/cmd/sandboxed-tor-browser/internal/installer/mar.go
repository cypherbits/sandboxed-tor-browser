// mar.go - Mozilla ARchive file routines.
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
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"cmd/sandboxed-tor-browser/internal/data"
)

var tbbMARCerts []*x509.Certificate

// VerifyTorBrowserMAR validates the MAR signature against the TBB MAR signing
// keys.
func VerifyTorBrowserMAR(mar []byte) error {
	marLen := len(mar)
	h := sha512.New()

	// HEADER:
	//  4 bytes : MARID - "MAR1"
	//  4 bytes : OffsetToIndex - offset to INDEX in bytes relative to the start of MAR file
	if len(mar) < 8 {
		return fmt.Errorf("missing/truncated MAR SIGNATURES")
	}
	if !bytes.Equal(mar[0:4], []byte{'M', 'A', 'R', '1'}) {
		return fmt.Errorf("corrupted MAR header")
	}
	if offsetToIndex := binary.BigEndian.Uint32(mar[4:8]); int(offsetToIndex) > marLen {
		return fmt.Errorf("offsetToIndex (%v) larger than MAR (%v)", offsetToIndex, marLen)
	}
	h.Write(mar[0:8])
	mar = mar[8:]

	// SIGNATURES:
	//   8 bytes : FileSize - size in bytes of the entire MAR file
	//   4 bytes : NumSignatures - Number of signatures
	//
	// Note: Per the documentation certain MARs can be missing this entirely.
	// This isn't handled particularly well, except that the FileSize is
	// enforced and will probably not match.
	if len(mar) < 12 {
		return fmt.Errorf("missing/truncated MAR SIGNATURES")
	}
	if fileSize := binary.BigEndian.Uint64(mar[0:8]); int(fileSize) != marLen {
		return fmt.Errorf("fileSize (%v) != MAR size (%v)", fileSize, marLen)
	}
	numSignatures := binary.BigEndian.Uint32(mar[8:12])
	if numSignatures == 0 || numSignatures > 8 {
		return fmt.Errorf("numSignatures (%v) violates constraints", numSignatures)
	}
	h.Write(mar[0:12])
	mar = mar[12:]

	var signatures [][]byte
	for i := 0; i < int(numSignatures); i++ {
		// SIGNATURE_ENTRY:
		//  4 bytes : SignatureAlgorithmID - ID representing the type of signature algorithm.
		//  4 bytes : SignatureSize - Size in bytes of the signature that follows
		//  N bytes : Signature - The signature of type SIGNATURE_ENTRY.SignatureAlgorithmID and size N = SIGNATURE_ENTRY.SignatureSize bytes
		if len(mar) < 8 {
			return fmt.Errorf("missing/truncated SIGNATURE_ENTRY")
		}
		signatureAlgorithmID := binary.BigEndian.Uint32(mar[0:4])
		if signatureAlgorithmID != 512 {
			// Tor Browser uses a custom signature algorithm ID.
			// See: bugs.torproject.org/13379
			return fmt.Errorf("invalid signature ID: %v", signatureAlgorithmID)
		}
		signatureSize := binary.BigEndian.Uint32(mar[4:8])
		if signatureSize > 2048 {
			return fmt.Errorf("signatureSize (%v) violates constraints", signatureSize)
		}
		h.Write(mar[0:8])
		mar = mar[8:]

		signatures = append(signatures, mar[0:signatureSize])

		// The signature doesn't cover itself, obviously.
		mar = mar[signatureSize:]
	}

	// Write out the rest of the MAR into the digest.
	h.Write(mar)
	digest := h.Sum(nil)

	// Validate the signatures.
	validSigs := 0
	for _, sig := range signatures {
		// MAR signature entries don't have information regarding which public
		// keys were used for signing, at all.  This is totally fucking
		// retarded, and the only thing that's possible is to check each
		// sig against all possible public keys.
		//
		// Apparently the Tor Browser developers are trying to transition to
		// a new MAR signing key as well.
		//
		// See: https://bugs.torproject.org/18008
		for _, cert := range tbbMARCerts {
			k, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				continue
			}
			if err := rsa.VerifyPKCS1v15(k, crypto.SHA512, digest[:], sig); err == nil {
				validSigs++
			}
		}
	}

	if validSigs <= 0 || validSigs > int(numSignatures) {
		return fmt.Errorf("signature verification error")
	}

	return nil
}

func init() {
	assets := []string{
		"installer/release_primary_6.5.der", // Stable MAR signing key.
		"installer/release_primary.der",     // (Unused) MAR signing key.
		"installer/release_secondary.der",   // Alpha MAR signing key (7.0).
	}

	for _, asset := range assets {
		if der, err := data.Asset(asset); err != nil {
			panic(err)
		} else if cert, err := x509.ParseCertificate(der); err != nil {
			panic("failed to parse TBB MAR signing cert:" + err.Error())
		} else {
			tbbMARCerts = append(tbbMARCerts, cert)
		}
	}
}
