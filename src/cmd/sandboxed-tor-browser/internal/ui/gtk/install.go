// install.go - Gtk+ install user interface routines.
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

package gtk

import (
	gtk3 "github.com/gotk3/gotk3/gtk"

	sbui "cmd/sandboxed-tor-browser/internal/ui"
	"cmd/sandboxed-tor-browser/internal/ui/async"
)

type installDialog struct {
	ui *gtkUI

	dialog             *gtk3.Dialog
	channelSelector    *gtk3.ComboBoxText
	localeSelector     *gtk3.ComboBoxText
	systemTorIndicator *gtk3.Box
}

func (d *installDialog) run() bool {
	defer d.dialog.Hide()
	return d.dialog.Run() == int(gtk3.RESPONSE_OK)
}

func (d *installDialog) onCancel() {
	d.ui.onDestroy()
}

func (d *installDialog) onOk() error {
	// Reflect the will of the user in the config structure, and write the
	// config to disk.
	d.ui.Cfg.SetChannel(d.channelSelector.GetActiveText())
	d.ui.Cfg.SetLocale(d.localeSelector.GetActiveText())
	if err := d.ui.Cfg.Sync(); err != nil {
		return err
	}

	// No install to be done.
	if !d.ui.NeedsInstall() && !d.ui.ForceInstall {
		return nil
	}

	// Configure the progress bar dialog.
	d.ui.progressDialog.setTitle("Installing Tor Browser")
	d.ui.progressDialog.setText("Initializing installation process...")

	// Display the progress dialog, and start the install task.
	async := async.NewAsync()
	d.ui.progressDialog.run(async, func() { d.ui.DoInstall(async) })
	return async.Err
}

func (d *installDialog) onChannelChanged() {
	// Repopulate the locale dropdown, based on the currently selected locale,
	// for the new channel.
	ch := d.channelSelector.GetActiveText()
	l := d.localeSelector.GetActiveText()
	if l == "" {
		// Use the configured value if there isn't a current sensible selection.
		l = d.ui.Cfg.Locale
	}
	d.localeSelector.RemoveAll()
	canSetLocale := false
	for _, v := range sbui.BundleLocales[ch] {
		if v == l {
			canSetLocale = true
		}
		d.localeSelector.Append(v, v)
	}
	if canSetLocale {
		d.localeSelector.SetActiveID(l)
	} else {
		d.localeSelector.SetActive(0)
	}
}

func (ui *gtkUI) initInstallDialog(b *gtk3.Builder) error {
	d := new(installDialog)
	d.ui = ui

	obj, err := b.GetObject("installDialog")
	if err != nil {
		return err
	}

	ok := false
	if d.dialog, ok = obj.(*gtk3.Dialog); !ok {
		return newInvalidBuilderObject(obj)
	} else {
		d.dialog.SetDefaultResponse(gtk3.RESPONSE_CANCEL)
		d.dialog.SetIcon(ui.iconPixbuf)
		d.dialog.SetTransientFor(ui.mainWindow)
	}

	// Images.
	if img, err := getImage(b, "installLogo"); err != nil {
		return err
	} else {
		img.SetFromPixbuf(ui.logoPixbuf)
	}

	if d.channelSelector, err = getComboBoxText(b, "channelSelector"); err != nil {
		return err
	} else {
		id := ""
		for _, v := range sbui.BundleChannels[ui.Cfg.Architecture] {
			if v == ui.Cfg.Channel {
				id = v
			}
			d.channelSelector.Append(v, v)
		}
		if id != "" {
			d.channelSelector.SetActiveID(id)
		} else {
			d.channelSelector.SetActive(0)
		}
		d.channelSelector.Connect("changed", func() { d.onChannelChanged() })
	}
	if d.localeSelector, err = getComboBoxText(b, "localeSelector"); err != nil {
		return err
	}
	d.onChannelChanged()
	if d.systemTorIndicator, err = getBox(b, "installSystemTorIndicator"); err != nil {
		return err
	}
	d.systemTorIndicator.SetVisible(ui.Cfg.UseSystemTor)

	ui.installDialog = d
	return nil
}
