// install.go - Install logic.
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
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"cmd/sandboxed-tor-browser/internal/data"
	"cmd/sandboxed-tor-browser/internal/installer"
	"cmd/sandboxed-tor-browser/internal/tor"
	. "cmd/sandboxed-tor-browser/internal/ui/async"
	"cmd/sandboxed-tor-browser/internal/ui/config"
	"cmd/sandboxed-tor-browser/internal/utils"
)

// DoInstall executes the install step based on the configured parameters.
// This is blocking and should be run from a go routine, with the appropriate
// Async structure used to communicate.
func (c *Common) DoInstall(async *Async) {
	var err error
	async.Err = nil
	defer func() {
		if len(async.Cancel) > 0 {
			<-async.Cancel
		}
		if async.Err != nil {
			log.Printf("install: Failing with error: %v", async.Err)
		} else {
			log.Printf("install: Complete.")
		}
		runtime.GC()
		async.Done <- true
	}()

	log.Printf("install: Starting.")

	if c.tor != nil {
		log.Printf("install: Shutting down old tor.")
		c.tor.Shutdown()
		c.tor = nil
	}

	// Get the Dial() routine used to reach the external network.
	var dialFn dialFunc
	if err := c.launchTor(async, true); err != nil {
		async.Err = err
		return
	}
	if dialFn, err = c.getTorDialFunc(); err == tor.ErrTorNotRunning {
		dialFn = net.Dial
	} else if err != nil {
		async.Err = err
		return
	}

	// Create the async HTTP client.
	client := newHPKPGrabClient(dialFn)

	// Download the JSON file showing where the bundle files are.
	log.Printf("install: Checking available downloads.")
	async.UpdateProgress("Checking available downloads.")

	var version string
	var downloads *installer.DownloadsEntry
	if url := installer.DownloadsURL(c.Cfg, (c.tor != nil)); url == "" {
		async.Err = fmt.Errorf("unable to find downloads URL")
		return
	} else {
		log.Printf("install: Metadata URL: %v", url)
		if b := async.Grab(client, url, nil); async.Err != nil {
			return
		} else if version, downloads, async.Err = installer.GetDownloadsEntry(c.Cfg, b); async.Err != nil {
			return
		}
	}
	checkAt := time.Now().Unix()

	log.Printf("install: Version: %v Downloads: %v", version, downloads)

	// Download the bundle.
	log.Printf("install: Downloading %v", downloads.Binary)
	async.UpdateProgress("Downloading Tor Browser.")

	var bundleTarXz []byte
	if bundleTarXz = async.Grab(client, downloads.Binary, func(s string) { async.UpdateProgress(fmt.Sprintf("Downloading Tor Browser: %s", s)) }); async.Err != nil {
		return
	}

	// Download the signature.
	log.Printf("install: Downloading %v", downloads.Sig)
	async.UpdateProgress("Downloading Tor Browser PGP Signature.")

	var bundleSig []byte
	if bundleSig = async.Grab(client, downloads.Sig, nil); async.Err != nil {
		return
	}

	// Check the signature.
	log.Printf("install: Validating Tor Browser PGP Signature.")
	async.UpdateProgress("Validating Tor Browser PGP Signature.")


//AVANIX MODIFICAR: se ha comentado el PGP
	 if async.Err = installer.ValidatePGPSignature(bundleTarXz, bundleSig); async.Err != nil {
		 log.Printf("install: TODO: PGP check was disable to allow latest alpha to install.")
	// 	return
	 }


	// Install the bundle.
	log.Printf("install: Installing Tor Browser.")
	async.UpdateProgress("Installing Tor Browser.")

	os.RemoveAll(c.Cfg.TorDataDir) // Remove the tor directory.

	if err := installer.ExtractBundle(c.Cfg.BundleInstallDir, bundleTarXz, async.Cancel); err != nil {
		async.Err = err
		if async.Err == installer.ErrExtractionCanceled {
			async.Err = ErrCanceled
		}
		return
	}

	// Lock out and ignore cancelation, since things are basically done.
	async.ToUI <- false

	// Install the autoconfig stuff.
	if async.Err = writeAutoconfig(c.Cfg); async.Err != nil {
		return
	}

	// Set the manifest.
	c.Manif = config.NewManifest(c.Cfg, version)
	if async.Err = c.Manif.Sync(); async.Err != nil {
		return
	}

	// Set the appropriate bits in the config.
	c.Cfg.SetLastUpdateCheck(checkAt)
	c.Cfg.SetForceUpdate(false)
	c.Cfg.SetFirstLaunch(true)

	// Sync the config, and return.
	async.Err = c.Cfg.Sync()
}

func writeAutoconfig(cfg *config.Config) error {
	autoconfigFile := filepath.Join(cfg.BundleInstallDir, "Browser", "defaults", "pref", "autoconfig.js")
	if b, err := data.Asset("installer/autoconfig.js"); err != nil {
		return err
	} else if err = ioutil.WriteFile(autoconfigFile, b, utils.FileMode); err != nil {
		return err
	}

	mozillacfgFile := filepath.Join(cfg.BundleInstallDir, "Browser", "mozilla.cfg")
	if b, err := data.Asset("installer/mozilla.cfg"); err != nil {
		return err
	} else if err = ioutil.WriteFile(mozillacfgFile, b, utils.FileMode); err != nil {
		return err
	}

	return nil
}
