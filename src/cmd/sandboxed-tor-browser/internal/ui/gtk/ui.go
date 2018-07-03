// ui.go - Gtk+ user interface routines.
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

// Package gtk implements a Gtk+ user interface.
package gtk

import (
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/gotk3/gotk3/gdk"
	gtk3 "github.com/gotk3/gotk3/gtk"

	"cmd/sandboxed-tor-browser/internal/data"
	"cmd/sandboxed-tor-browser/internal/installer"
	sbui "cmd/sandboxed-tor-browser/internal/ui"
	"cmd/sandboxed-tor-browser/internal/ui/async"
	"cmd/sandboxed-tor-browser/internal/ui/notify"
	. "cmd/sandboxed-tor-browser/internal/utils"
)

const actionRestart = "restart"

type gtkUI struct {
	sbui.Common

	logoPixbuf *gdk.Pixbuf
	iconPixbuf *gdk.Pixbuf
	mainWindow *gtk3.Window // Always hidden.

	installDialog  *installDialog
	configDialog   *configDialog
	progressDialog *progressDialog

	updateNotification   *notify.Notification
	updateNotificationCh chan string
}

func (ui *gtkUI) Run() error {
	const (
		updateMinInterval   = 30 * time.Second
		updateCheckInterval = 2 * time.Hour
		updateNagInterval   = 15 * time.Minute
		gtkPumpInterval     = 1 * time.Second
	)

	if err := ui.Common.Run(); err != nil {
		ui.bitch("Failed to run common UI: %v", err)
		return err
	}
	if ui.PrintVersion {
		return nil
	}
	if ui.updateNotification == nil {
		log.Printf("ui: libnotify wasn't found, no desktop notifications possible")
	}

	if ui.WasHardened {
		log.Printf("ui: Previous `hardened` bundle detected")

		ok := ui.ask("The hardened bundle has been discontinued, and the installation of a supported bundle is required.\n\nWARNING: The install process will delete the existing bundle, including bookmarks and downloads.  Backup all data you wish to preserve before continuing.")
		if !ok {
			log.Printf("ui: User denied `hardened` bundle overwrite")
			return nil
		}
		log.Printf("ui: User confirmed `hardened` bundle overwrite")
	}

	if ui.NeedsInstall() || ui.ForceInstall {
		for {
			if !ui.installDialog.run() {
				ui.onDestroy()
				return nil
			} else {
				if err := ui.installDialog.onOk(); err != nil {
					if err != async.ErrCanceled {
						ui.bitch("Failed to install: %v", err)
						return err
					}
					continue
				}
				ui.ForceInstall = false
				break
			}
		}
	}

	for {
		// Configuration.
		if ui.ForceConfig || ui.Cfg.FirstLaunch {
			if !ui.configDialog.run() {
				ui.onDestroy()
				return nil
			} else if err := ui.configDialog.onOk(); err != nil {
				ui.bitch("Failed to write config: %v", err)
				continue
			}
		}
		ui.ForceConfig = true // Drop back to the config on failures.

		// Launch
		if err := ui.launch(); err != nil {
			if err != async.ErrCanceled {
				ui.bitch("Failed to launch Tor Browser: %v", err)
			}
			continue
		}

		// Unset the first launch flag to skip the config on subsequent
		// launches.
		ui.Cfg.SetFirstLaunch(false)
		ui.Cfg.Sync()

		waitCh := make(chan error)
		go func() {
			waitCh <- ui.Sandbox.Wait()
		}()

		// Determine the time for the initial update check.
		initialUpdateInterval := updateMinInterval
		oldScheduledTime := time.Unix(ui.Cfg.LastUpdateCheck, 0).Add(updateCheckInterval)
		Debugf("update: Previous scheduled update check: %v", oldScheduledTime)

		if oldScheduledTime.After(time.Now()) {
			deltaT := oldScheduledTime.Sub(time.Now())
			if deltaT > updateMinInterval {
				initialUpdateInterval = deltaT
			}
		}
		Debugf("update: Initial scheduled update check: %v", initialUpdateInterval)

		updateTimer := time.NewTimer(initialUpdateInterval)
		defer updateTimer.Stop()

		gtkPumpTicker := time.NewTicker(gtkPumpInterval)
		defer gtkPumpTicker.Stop()

		var update *installer.UpdateEntry
	browserRunningLoop:
		for {
			select {
			case err := <-waitCh:
				return err
			case <-gtkPumpTicker.C:
				// This is so stupid, but is needed for notification actions
				// to work.
				gtk3.MainIterationDo(false)
				continue
			case action := <-ui.updateNotificationCh:
				// Notification action was triggered, probably a restart.
				log.Printf("update: Received notification action: %v", action)
				if action == actionRestart {
					break browserRunningLoop
				}
				continue
			case <-updateTimer.C:
			}

			updateTimer.Stop()

			// Only re-check for updates if we think we are up to date.
			// Skipping re-fetching the metadata is fine, because we will
			// do it as part of doUpdate() after the restart if it has
			// aged too much.
			if !ui.Cfg.ForceUpdate {
				log.Printf("update: Starting scheduled update check.")

				// Check for an update in the background.
				async := async.NewAsync()
				async.UpdateProgress = func(s string) {}

				go func() {
					update = ui.CheckUpdate(async)
					async.Done <- true
				}()

				/// Wait for the check to complete.
				select {
				case err := <-waitCh: // User exited browser while checking.
					return err
				case <-async.Done:
				}

				if async.Err != nil {
					log.Printf("update: Failed background update check: %v", async.Err)
				}

				if update != nil {
					log.Printf("update: An update is available: %v", update.DisplayVersion)
				} else {
					log.Printf("update: The bundle is up to date")
				}
			}

			if ui.Cfg.ForceUpdate {
				log.Printf("update: Displaying notification.")
				ui.notifyUpdate(update)
				updateTimer.Reset(updateNagInterval)
			} else {
				updateTimer.Reset(updateCheckInterval)
			}
		}

		// If we are here, the user wants to restart to apply an update.
		gtkPumpTicker.Stop()

		if ui.updateNotification != nil {
			ui.updateNotification.Close()
		}

		// Kill the browser.  It's not as if firefox does the right thing on
		// SIGTERM/SIGINT and we have the pid of init inside the sandbox
		// anyway...
		//
		// https://bugzilla.mozilla.org/show_bug.cgi?id=336193
		ui.Sandbox.Kill()
		<-waitCh

		ui.Sandbox = nil
		ui.PendingUpdate = update
		ui.ForceConfig = false
		ui.NoKillTor = true // Don't re-lauch tor on the first pass.
	}
}

func (ui *gtkUI) Term() {
	// By the time this is run, we have exited the Gtk+ event loop, so we
	// can assume we have exclusive ownership of the UI state.
	ui.Common.Term()

	if ui.updateNotification != nil {
		ui.updateNotification.Close()
		ui.updateNotification = nil
		notify.Uninit()
	}
}

func Init() (sbui.UI, error) {
	var err error

	// Create the UI object and initialize the common state.
	ui := new(gtkUI)
	if err = ui.Init(); err != nil {
		return nil, err
	}

	// Initialize Gtk+.  Past this point, we can use dialog boxes to
	// convey fatal errors.
	gtk3.Init(nil)

	if ui.logoPixbuf, err = ui.pixbufFromAsset("ui/tbb-logo.svg"); err != nil {
		return nil, err
	}
	if ui.iconPixbuf, err = ui.pixbufFromAsset("ui/default48.png"); err != nil {
		return nil, err
	}
	if ui.mainWindow, err = gtk3.WindowNew(gtk3.WINDOW_TOPLEVEL); err != nil {
		return nil, err
	}

	// Load the UI.
	if b, err := gtk3.BuilderNew(); err != nil {
		return nil, err
	} else if d, err := data.Asset("ui/gtkui.ui"); err != nil {
		return nil, err
	} else if err = b.AddFromString(string(d)); err != nil {
		return nil, err
	} else {
		// Installation dialog.
		if err := ui.initInstallDialog(b); err != nil {
			return nil, err
		}

		// Configuration dialog.
		if err := ui.initConfigDialog(b); err != nil {
			return nil, err
		}

		// Progress bar dialog.
		if err := ui.initProgressDialog(b); err != nil {
			return nil, err
		}
	}

	// Initialize the Desktop Notification interface.
	if err = notify.Init("Sandboxed Tor Browser"); err == nil {
		ui.updateNotification = notify.New("", "", ui.iconPixbuf)
		ui.updateNotification.SetTimeout(15 * 1000)
		ui.updateNotification.AddAction(actionRestart, "Restart Now")
		ui.updateNotificationCh = ui.updateNotification.ActionChan()
	} else {
		ui.updateNotificationCh = make(chan string)
	}

	return ui, nil
}

func (ui *gtkUI) onDestroy() {
	ui.Cfg.ResetDirty()
}

func (ui *gtkUI) launch() error {
	// If we don't need to update, and would just launch, quash the UI.
	checkUpdate := ui.Cfg.ForceUpdate || ui.Cfg.NeedsUpdateCheck()
	squelchUI := !checkUpdate && ui.Cfg.UseSystemTor

	async := async.NewAsync()
	if squelchUI {
		async.UpdateProgress = func(s string) {}
		go ui.DoLaunch(async, checkUpdate)
		<-async.Done
	} else {
		ui.progressDialog.setTitle("Launching Tor Browser")
		ui.progressDialog.setText("Initializing startup process...")
		ui.progressDialog.run(async, func() { ui.DoLaunch(async, checkUpdate) })
	}

	return async.Err
}

func (ui *gtkUI) bitch(format string, a ...interface{}) {
	// XXX: Make this nicer with like, an icon and shit.
	md := gtk3.MessageDialogNew(ui.mainWindow, gtk3.DIALOG_MODAL, gtk3.MESSAGE_ERROR, gtk3.BUTTONS_OK, format, a...)
	md.Run()
	md.Hide()
	ui.forceRedraw()
}

func (ui *gtkUI) ask(format string, a ...interface{}) bool {
	md := gtk3.MessageDialogNew(ui.mainWindow, gtk3.DIALOG_MODAL, gtk3.MESSAGE_QUESTION, gtk3.BUTTONS_OK_CANCEL, format, a...)
	result := md.Run()
	md.Hide()
	ui.forceRedraw()

	return result == int(gtk3.RESPONSE_OK)
}

func (ui *gtkUI) notifyUpdate(update *installer.UpdateEntry) {
	if update == nil {
		panic("ui: notifyUpdate called with no update metadata")
	}

	if ui.updateNotification != nil {
		ui.updateNotification.Update("A Tor Browser update is available.", "Please restart to update to version "+update.DisplayVersion+".", ui.iconPixbuf)
		ui.updateNotification.Show()
	}
}

func (ui *gtkUI) pixbufFromAsset(asset string) (*gdk.Pixbuf, error) {
	d, err := data.Asset(asset)
	if err != nil {
		return nil, err
	}

	l, err := gdk.PixbufLoaderNewWithType(strings.TrimLeft(filepath.Ext(asset), "."))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(d); {
		n, err := l.Write(d)
		if err != nil {
			return nil, err
		}
		d = d[n:]
		i += n
	}
	l.Close()

	return l.GetPixbuf()
}

func (ui *gtkUI) forceRedraw() {
	for gtk3.EventsPending() {
		gtk3.MainIteration()
	}
}
