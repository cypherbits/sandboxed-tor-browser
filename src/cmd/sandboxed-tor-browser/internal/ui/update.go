// update.go - Update logic.
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

package ui

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"cmd/sandboxed-tor-browser/internal/installer"
	"cmd/sandboxed-tor-browser/internal/sandbox"
	"cmd/sandboxed-tor-browser/internal/tor"
	. "cmd/sandboxed-tor-browser/internal/ui/async"
)

// CheckUpdate queries the update server to see if an update for the current
// bundle is available.
func (c *Common) CheckUpdate(async *Async) *installer.UpdateEntry {
	//Disable Updating until we work on the new .mar updates
	return nil

	
	// Check for updates.
	log.Printf("update: Checking for updates.")
	async.UpdateProgress("Checking for updates.")

	// Create the async HTTP client.
	if c.tor == nil {
		async.Err = tor.ErrTorNotRunning
		return nil
	}
	dialFn, err := c.getTorDialFunc()
	if err != nil {
		async.Err = err
		return nil
	}

	client := newHPKPGrabClient(dialFn)

	// Determine where the update metadata should be fetched from.
	updateURLs := []string{}
	for _, b := range []bool{true, false} { // Prioritize .onions.
		if url, err := installer.UpdateURL(c.Manif, b); err != nil {
			log.Printf("update: Failed to get update URL (onion: %v): %v", b, err)
		} else {
			updateURLs = append(updateURLs, url)
		}
	}
	if len(updateURLs) == 0 {
		log.Printf("update: Failed to find any update URLs")
		async.Err = fmt.Errorf("failed to find any update URLs")
		return nil
	}

	// Check the version, by downloading the XML file.
	var update *installer.UpdateEntry
	fetchOk := false
	for _, url := range updateURLs {
		log.Printf("update: Metadata URL: %v", url)
		async.Err = nil // Clear errors per fetch.
		if b := async.Grab(client, url, nil); async.Err == ErrCanceled {
			return nil
		} else if async.Err != nil {
			log.Printf("update: Metadata download failed: %v", async.Err)
			continue
		} else if update, async.Err = installer.GetUpdateEntry(b); async.Err != nil {
			log.Printf("update: Metadata parse failed: %v", async.Err)
			continue
		}
		fetchOk = true
		break
	}

	if !fetchOk {
		// The last update attempt likely isn't the only relevant error,
		// just set this to something that won't terrify users, more detailed
		// diagnostics are avaialble in the log.
		async.Err = fmt.Errorf("failed to download update metadata")
		return nil
	}
	checkAt := time.Now().Unix()

	// If there is an update, tag the installed bundle as stale...
	if update == nil {
		log.Printf("update: Installed bundle is current.")
		c.Cfg.SetForceUpdate(false)
	} else if !c.Manif.BundleUpdateVersionValid(update.AppVersion) {
		log.Printf("update: Update server provided a downgrade: '%v'", update.AppVersion)
		async.Err = fmt.Errorf("update server provided a downgrade: '%v'", update.AppVersion)
		return nil
	} else {
		log.Printf("update: Installed bundle needs updating.")
		c.Cfg.SetForceUpdate(true)
	}
	c.Cfg.SetLastUpdateCheck(checkAt)

	// ... and flush the config.
	if async.Err = c.Cfg.Sync(); async.Err != nil {
		return nil
	}

	return update
}

// FetchUpdate downloads the update specified by the patch over tor, and
// validates it with the hash in the patch datastructure, and the known MAR
// signing keys.
func (c *Common) FetchUpdate(async *Async, patch *installer.Patch) []byte {
	// Launch the tor daemon if needed.
	if c.tor == nil {
		async.Err = c.launchTor(async, false)
		if async.Err != nil {
			return nil
		}
	}
	dialFn, err := c.getTorDialFunc()
	if err != nil {
		async.Err = err
		return nil
	}

	// Download the MAR file.
	log.Printf("update: Downloading %v", patch.Url)
	async.UpdateProgress("Downloading Tor Browser Update.")

	var mar []byte
	client := newHPKPGrabClient(dialFn)
	if mar = async.Grab(client, patch.Url, func(s string) { async.UpdateProgress(fmt.Sprintf("Downloading Tor Browser Update: %s", s)) }); async.Err != nil {
		return nil
	}

	log.Printf("update: Validating Tor Browser Update.")
	async.UpdateProgress("Validating Tor Browser Update.")

	// Validate the size against that listed in the XML file.
	if len(mar) != patch.Size {
		async.Err = fmt.Errorf("downloaded patch size does not match patch metadata")
		return nil
	}

	// Validate the hash against that listed in the XML file.
	expectedHash, err := hex.DecodeString(patch.HashValue)
	if err != nil {
		async.Err = fmt.Errorf("failed to decode HashValue: %v", err)
		return nil
	}
	switch patch.HashFunction {
	case "SHA512":
		derivedHash := sha512.Sum512(mar)
		if !bytes.Equal(expectedHash, derivedHash[:]) {
			async.Err = fmt.Errorf("downloaded hash does not match patch metadata")
			return nil
		}
	default:
		async.Err = fmt.Errorf("unsupported hash function: '%v'", patch.HashFunction)
		return nil
	}

	// ... and verify the signature block in the MAR with our copy of the key.
	if async.Err = installer.VerifyTorBrowserMAR(mar); async.Err != nil {
		return nil
	}

	return mar
}

func (c *Common) doUpdate(async *Async) {
	// This attempts to follow the process that Firefox uses to check for
	// updates.  https://wiki.mozilla.org/Software_Update:Checking_For_Updates

	const (
		patchPartial  = "partial"
		patchComplete = "complete"
	)

	// Check for updates, unless we have sufficiently fresh metatdata already.
	var update *installer.UpdateEntry
	if c.PendingUpdate != nil && !c.Cfg.NeedsUpdateCheck() {
		update = c.PendingUpdate
		c.PendingUpdate = nil
	} else {
		update = c.CheckUpdate(async)
		if async.Err != nil || update == nil {
			// Something either broke, or the bundle is up to date.  The caller
			// needs to check async.Err, and either way there's nothing more that
			// can be done.
			return
		}
		c.PendingUpdate = nil
	}

	// Figure out the best MAR to download.
	patches := make(map[string]*installer.Patch)
	for i := 0; i < len(update.Patch); i++ {
		v := &update.Patch[i]
		if patches[v.Type] != nil {
			async.Err = fmt.Errorf("duplicate patch entry for kind: '%v'", v.Type)
			return
		}
		patches[v.Type] = v
	}

	patchTypes := []string{}
	if !c.Cfg.SkipPartialUpdate {
		patchTypes = append(patchTypes, patchPartial)
	}
	patchTypes = append(patchTypes, patchComplete)

	// Cycle through the patch types, and apply the "best" one.
	nrAttempts := 0
	for _, patchType := range patchTypes {
		async.Err = nil

		patch := patches[patchType]
		if patch == nil {
			continue
		}

		nrAttempts++
		mar := c.FetchUpdate(async, patch)
		if async.Err == ErrCanceled {
			return
		} else if async.Err != nil {
			log.Printf("update: Failed to fetch update: %v", async.Err)
			continue
		}
		if mar == nil {
			panic("update: no MAR returned from successful fetch")
		}

		// Shutdown the old tor now.
		if c.tor != nil {
			log.Printf("update: Shutting down old tor.")
			c.tor.Shutdown()
			c.tor = nil
		}

		// Apply the update.
		log.Printf("update: Updating Tor Browser.")
		async.UpdateProgress("Updating Tor Browser.")

		async.ToUI <- false //  Lock out canceling.

		if async.Err = sandbox.RunUpdate(c.Cfg, mar); async.Err != nil {
			log.Printf("update: Failed to apply update: %v", async.Err)
			if patchType == patchPartial {
				c.Cfg.SetSkipPartialUpdate(true)
				if async.Err = c.Cfg.Sync(); async.Err != nil {
					return
				}
			}
			async.ToUI <- true // Unlock canceling.
			continue
		}

		// Failures past this point are catastrophic in that, the on-disk
		// bundle is up to date, but the post-update tasks have failed.

		// Reinstall the autoconfig stuff.
		if async.Err = writeAutoconfig(c.Cfg); async.Err != nil {
			return
		}

		// Update the maniftest and config.
		c.Manif.SetVersion(update.AppVersion)
		if async.Err = c.Manif.Sync(); async.Err != nil {
			return
		}
		c.Cfg.SetForceUpdate(false)
		c.Cfg.SetSkipPartialUpdate(false)
		if async.Err = c.Cfg.Sync(); async.Err != nil {
			return
		}

		async.ToUI <- true // Unlock canceling.

		// Restart tor if we launched it.
		if !c.Cfg.UseSystemTor {
			log.Printf("launch: Reconnecting to the Tor network.")
			async.UpdateProgress("Reconnecting to the Tor network.")
			async.Err = c.launchTor(async, false)
		}

		return
	}

	if nrAttempts == 0 {
		async.Err = fmt.Errorf("no suitable MAR file found")
	} else if async.Err != ErrCanceled {
		async.Err = fmt.Errorf("failed to apply all possible MAR files")
	}
	return
}
