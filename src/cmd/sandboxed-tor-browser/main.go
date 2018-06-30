// main.go - sandboxed-tor-browser
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

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"cmd/sandboxed-tor-browser/internal/ui/gtk"
)

func main() {
	// Disable dumping core and ptrace().
	if ret, _, err := syscall.Syscall6(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0, 0, 0, 0); ret != 0 {
		log.Fatalf("failed to disable core dumps: %v", err)
		return
	}

	// Install the signal handlers before initializing the UI.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, os.Kill, syscall.SIGTERM)

	// Initialize the UI.
	ui, err := gtk.Init()
	if err != nil {
		log.Fatalf("failed to initialize user interface: %v", err)
	}
	defer ui.Term()

	// Launch the UI in a go routine so that clean up happens.
	doneCh := make(chan interface{})
	go func() {
		defer func() { doneCh <- true }()
		if err := ui.Run(); err != nil {
			log.Printf("fatal error in the user interface: %v", err)
		}
	}()

	// Wait for the actual work to finish, or a fatal signal to be received.
	select {
	case _ = <-doneCh:
		// Goroutine terminated.
	case sig := <-sigCh:
		// Caught a signal handler.
		log.Printf("exiting on signal: %v", sig)
	}
}
