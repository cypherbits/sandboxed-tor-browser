// launch.go - Launcher logic.
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
	"log"
	"runtime"

	"cmd/sandboxed-tor-browser/internal/sandbox"
	. "cmd/sandboxed-tor-browser/internal/ui/async"
)

// DoLaunch executes the launch step based on the configured parameters.
// This is blocking and should be run from a go routine, with the appropriate
// Async structure used to communicate.
func (c *Common) DoLaunch(async *Async, checkUpdates bool) {
	async.Err = nil
	defer func() {
		if len(async.Cancel) > 0 {
			<-async.Cancel
		}
		if async.Err != nil {
			log.Printf("launch: Failing with error: %v", async.Err)
			if c.tor != nil {
				c.tor.Shutdown()
				c.tor = nil
			}
		} else {
			log.Printf("launch: Complete.")
		}
		runtime.GC()
		async.Done <- true
	}()

	log.Printf("launch: Starting.")

	// Ensure that we actually can launch.
	if c.NeedsInstall() {
		async.Err = fmt.Errorf("launch failed, installation required")
		return
	}

	// Start tor if required.
	log.Printf("launch: Connecting to the Tor network.")
	async.UpdateProgress("Connecting to the Tor network.")
	if async.Err = c.launchTor(async, false); async.Err != nil {
		return
	}

	// If an update check is needed, check for updates.
	if checkUpdates {
		c.doUpdate(async)
		if async.Err != nil {
			return
		}
	}

	// Launch the sandboxed Tor Browser.
	log.Printf("launch: Starting Tor Browser.")
	async.UpdateProgress("Starting Tor Browser.")

	c.Sandbox, async.Err = sandbox.RunTorBrowser(c.Cfg, c.Manif, c.tor)
}
