// config.go - Gtk+ config user interface routines.
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
	"fmt"
	"net"
	"strconv"
	"strings"

	gtk3 "github.com/gotk3/gotk3/gtk"

	sbui "cmd/sandboxed-tor-browser/internal/ui"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

type configDialog struct {
	loaded bool
	ui     *gtkUI

	dialog *gtk3.Dialog

	// Tor config elements.
	torConfigBox      *gtk3.Box
	torProxyToggle    *gtk3.CheckButton
	torProxyConfigBox *gtk3.Box
	torProxyType      *gtk3.ComboBoxText
	torProxyAddress   *gtk3.Entry
	torProxyPort      *gtk3.Entry
	torProxyAuthBox   *gtk3.Box
	torProxyUsername  *gtk3.Entry
	torProxyPassword  *gtk3.Entry

	torBridgeToggle         *gtk3.CheckButton
	torBridgeConfigBox      *gtk3.Box
	torBridgeInternal       *gtk3.RadioButton
	torBridgeInternalBox    *gtk3.Box
	torBridgeInternalType   *gtk3.ComboBoxText
	torBridgeCustom         *gtk3.RadioButton
	torBridgeCustomFrame    *gtk3.Frame
	torBridgeCustomEntry    *gtk3.TextView
	torBridgeCustomEntryBuf *gtk3.TextBuffer

	entryInsensitive *gtk3.TextTag

	torSystemIndicator *gtk3.Box

	// Sandbox config elements.
	pulseAudioSwitch      *gtk3.Switch
	avCodecSwitch         *gtk3.Switch
	circuitDisplaySwitch  *gtk3.Switch
	amnesiacProfileBox    *gtk3.Box
	amnesiacProfileSwitch *gtk3.Switch
	displayBox            *gtk3.Box
	displayEntry          *gtk3.Entry
	downloadsDirBox       *gtk3.Box
	downloadsDirChooser   *gtk3.FileChooserButton
	desktopDirBox         *gtk3.Box
	desktopDirChooser     *gtk3.FileChooserButton
}

const proxySOCKS4 = "SOCKS 4"

func (d *configDialog) loadFromConfig() {
	if d.loaded {
		return
	}
	// Populate the fields from the config.

	d.torProxyToggle.SetActive(d.ui.Cfg.Tor.UseProxy)
	d.proxyTypeFromCfg()
	if d.ui.Cfg.Tor.ProxyAddress != "" {
		d.torProxyAddress.SetText(d.ui.Cfg.Tor.ProxyAddress)
	}
	if d.ui.Cfg.Tor.ProxyPort != "" {
		d.torProxyPort.SetText(d.ui.Cfg.Tor.ProxyPort)
	}
	if d.ui.Cfg.Tor.ProxyUsername != "" {
		d.torProxyUsername.SetText(d.ui.Cfg.Tor.ProxyUsername)
	}
	if d.ui.Cfg.Tor.ProxyPassword != "" {
		d.torProxyPassword.SetText(d.ui.Cfg.Tor.ProxyPassword)
	}

	d.torBridgeToggle.SetActive(d.ui.Cfg.Tor.UseBridges)
	d.torBridgeInternal.SetActive(!d.ui.Cfg.Tor.UseCustomBridges)
	d.internalBridgeTypeFromCfg()
	d.torBridgeCustom.SetActive(d.ui.Cfg.Tor.UseCustomBridges)
	d.torBridgeCustomEntryBuf.SetText(d.ui.Cfg.Tor.CustomBridges)
	d.onBridgeTypeChanged()

	// Set the sensitivity based on the toggles.
	d.torProxyConfigBox.SetSensitive(d.torProxyToggle.GetActive())
	d.torBridgeConfigBox.SetSensitive(d.torBridgeToggle.GetActive())
	d.torConfigBox.SetSensitive(!d.ui.Cfg.UseSystemTor)
	d.torSystemIndicator.SetVisible(d.ui.Cfg.UseSystemTor)

	forceAdv := false
	d.pulseAudioSwitch.SetActive(d.ui.Cfg.Sandbox.EnablePulseAudio)
	d.avCodecSwitch.SetActive(d.ui.Cfg.Sandbox.EnableAVCodec)
	d.circuitDisplaySwitch.SetActive(d.ui.Cfg.Sandbox.EnableCircuitDisplay)
	d.amnesiacProfileSwitch.SetActive(d.ui.Cfg.Sandbox.EnableAmnesiacProfileDirectory)
	if d.ui.Cfg.Sandbox.EnableAmnesiacProfileDirectory {
		forceAdv = true
	}
	if d.ui.Cfg.Sandbox.Display != "" {
		d.displayEntry.SetText(d.ui.Cfg.Sandbox.Display)
		forceAdv = true
	}
	if d.ui.Cfg.Sandbox.DownloadsDir != "" {
		d.downloadsDirChooser.SetCurrentFolder(d.ui.Cfg.Sandbox.DownloadsDir)
		forceAdv = true
	}
	if d.ui.Cfg.Sandbox.DesktopDir != "" {
		d.desktopDirChooser.SetCurrentFolder(d.ui.Cfg.Sandbox.DesktopDir)
		forceAdv = true
	}

	// Hide certain options from the masses, that are probably confusing.
	for _, w := range []*gtk3.Box{d.amnesiacProfileBox, d.displayBox, d.downloadsDirBox, d.desktopDirBox} {
		w.SetVisible(d.ui.AdvancedConfig || forceAdv)
	}
	d.loaded = true
}

func (d *configDialog) onOk() error {
	// Validate and propagate the UI entries to the config.

	d.ui.Cfg.Tor.SetUseProxy(d.torProxyToggle.GetActive())
	d.ui.Cfg.Tor.SetProxyType(d.torProxyType.GetActiveText())
	if s, err := d.torProxyAddress.GetText(); err != nil {
		return err
	} else if s = strings.TrimSpace(s); s == "" {
		d.ui.Cfg.Tor.SetProxyAddress(s)
	} else if net.ParseIP(s) == nil {
		return fmt.Errorf("Malformed proxy address: '%v'", s)
	} else {
		d.ui.Cfg.Tor.SetProxyAddress(s)
	}
	if s, err := d.torProxyPort.GetText(); err != nil {
		return err
	} else if s = strings.TrimSpace(s); s == "" {
		d.ui.Cfg.Tor.SetProxyPort(s)
	} else if _, err := strconv.ParseUint(s, 10, 16); err != nil {
		return fmt.Errorf("Malformed proxy port: '%v'", s)
	} else {
		d.ui.Cfg.Tor.SetProxyPort(s)
	}
	if d.ui.Cfg.Tor.ProxyType == proxySOCKS4 {
		d.torProxyUsername.SetText("")
		d.torProxyPassword.SetText("")
	}
	if s, err := d.torProxyUsername.GetText(); err != nil {
		return err
	} else {
		d.ui.Cfg.Tor.SetProxyUsername(strings.TrimSpace(s))
	}
	if s, err := d.torProxyPassword.GetText(); err != nil {
		return err
	} else {
		d.ui.Cfg.Tor.SetProxyPassword(strings.TrimSpace(s))
	}
	if d.ui.Cfg.Tor.ProxyAddress == "" || d.ui.Cfg.Tor.ProxyPort == "" {
		d.ui.Cfg.Tor.SetUseProxy(false)
	}
	if (d.ui.Cfg.Tor.ProxyUsername != "" && d.ui.Cfg.Tor.ProxyPassword == "") ||
		(d.ui.Cfg.Tor.ProxyUsername == "" && d.ui.Cfg.Tor.ProxyPassword != "") {
		return fmt.Errorf("Both a proxy username and password must be specified.")
	}

	d.ui.Cfg.Tor.SetUseBridges(d.torBridgeToggle.GetActive())
	d.ui.Cfg.Tor.SetInternalBridgeType(d.torBridgeInternalType.GetActiveText())
	d.ui.Cfg.Tor.SetUseCustomBridges(d.torBridgeCustom.GetActive())

	start := d.torBridgeCustomEntryBuf.GetStartIter()
	end := d.torBridgeCustomEntryBuf.GetEndIter()
	if s, err := d.torBridgeCustomEntryBuf.GetText(start, end, false); err != nil {
		return err
	} else if s, err = sbui.ValidateBridgeLines(s); err != nil {
		return err
	} else {
		d.ui.Cfg.Tor.SetCustomBridges(s)
	}

	d.ui.Cfg.Sandbox.SetEnablePulseAudio(d.pulseAudioSwitch.GetActive())
	d.ui.Cfg.Sandbox.SetEnableAVCodec(d.avCodecSwitch.GetActive())
	d.ui.Cfg.Sandbox.SetEnableCircuitDisplay(d.circuitDisplaySwitch.GetActive())
	d.ui.Cfg.Sandbox.SetEnableAmnesiacProfileDirectory(d.amnesiacProfileSwitch.GetActive())
	if s, err := d.displayEntry.GetText(); err != nil {
		return err
	} else {
		d.ui.Cfg.Sandbox.SetDisplay(strings.TrimSpace(s))
	}
	d.ui.Cfg.Sandbox.SetDownloadsDir(d.downloadsDirChooser.GetFilename())
	d.ui.Cfg.Sandbox.SetDesktopDir(d.desktopDirChooser.GetFilename())
	return d.ui.Cfg.Sync()
}

func (d *configDialog) run() bool {
	d.loadFromConfig()
	defer func() {
		d.dialog.Hide()
		d.ui.forceRedraw()
	}()

	return d.dialog.Run() == int(gtk3.RESPONSE_OK)
}

func (d *configDialog) proxyTypeFromCfg() {
	t := d.ui.Cfg.Tor.ProxyType
	if t == "" {
		d.torProxyType.SetActive(0)
	} else {
		d.torProxyType.SetActiveID(t)
	}
	d.onProxyTypeChanged()
}

func (d *configDialog) internalBridgeTypeFromCfg() {
	t := d.ui.Cfg.Tor.InternalBridgeType
	if t == "" {
		t = sbui.DefaultBridgeTransport
	}
	d.torBridgeInternalType.SetActiveID(t)
}

func (d *configDialog) onProxyTypeChanged() {
	d.torProxyAuthBox.SetSensitive(d.torProxyType.GetActiveText() != proxySOCKS4)
}

func (d *configDialog) onBridgeTypeChanged() {
	isInternal := d.torBridgeInternal.GetActive()
	d.torBridgeInternalBox.SetSensitive(isInternal)
	d.torBridgeCustomFrame.SetSensitive(!isInternal)
	d.updateBridgeEntrySensitive()
}

func (d *configDialog) updateBridgeEntrySensitive() {
	isInternal := d.torBridgeInternal.GetActive()
	start := d.torBridgeCustomEntryBuf.GetStartIter()
	end := d.torBridgeCustomEntryBuf.GetEndIter()

	if !isInternal && d.torBridgeToggle.GetActive() {
		d.torBridgeCustomEntryBuf.RemoveTag(d.entryInsensitive, start, end)
	} else {
		d.torBridgeCustomEntryBuf.ApplyTag(d.entryInsensitive, start, end)
	}
}

func (ui *gtkUI) initConfigDialog(b *gtk3.Builder) error {
	d := new(configDialog)
	d.ui = ui

	obj, err := b.GetObject("configDialog")
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

	if d.torConfigBox, err = getBox(b, "torConfigBox"); err != nil {
		return err
	}
	if d.torSystemIndicator, err = getBox(b, "cfgSystemTorIndicator"); err != nil {
		return err
	}

	// Tor Proxy config elements.
	if d.torProxyToggle, err = getCheckButton(b, "torProxyToggle"); err != nil {
		return err
	} else {
		d.torProxyToggle.Connect("toggled", func() {
			d.torProxyConfigBox.SetSensitive(d.torProxyToggle.GetActive())
		})
	}
	if d.torProxyConfigBox, err = getBox(b, "torProxyConfigBox"); err != nil {
		return err
	}
	if d.torProxyType, err = getComboBoxText(b, "torProxyType"); err != nil {
		return err
	} else {
		for _, v := range config.TorProxyTypes {
			d.torProxyType.Append(v, v)
		}
		d.torProxyType.Connect("changed", func() { d.onProxyTypeChanged() })
	}
	if d.torProxyAddress, err = getEntry(b, "torProxyAddress"); err != nil {
		return err
	}
	if d.torProxyPort, err = getEntry(b, "torProxyPort"); err != nil {
		return err
	}
	if d.torProxyAuthBox, err = getBox(b, "torProxyAuthBox"); err != nil {
		return err
	}
	if d.torProxyUsername, err = getEntry(b, "torProxyUsername"); err != nil {
		return err
	}
	if d.torProxyPassword, err = getEntry(b, "torProxyPassword"); err != nil {
		return err
	}

	// Tor Bridge config elements.
	if d.torBridgeToggle, err = getCheckButton(b, "torBridgeToggle"); err != nil {
		return err
	} else {
		d.torBridgeToggle.Connect("toggled", func() {
			d.torBridgeConfigBox.SetSensitive(d.torBridgeToggle.GetActive())
			d.updateBridgeEntrySensitive()
		})
	}
	if d.torBridgeConfigBox, err = getBox(b, "torBridgeConfigBox"); err != nil {
		return err
	}
	if d.torBridgeInternal, err = getRadioButton(b, "torBridgeInternal"); err != nil {
		return err
	} else {
		d.torBridgeInternal.Connect("toggled", func() { d.onBridgeTypeChanged() })
	}
	if d.torBridgeInternalBox, err = getBox(b, "torBridgeInternalBox"); err != nil {
		return err
	}
	if d.torBridgeInternalType, err = getComboBoxText(b, "torBridgeInternalType"); err != nil {
		return err
	} else {
		for transport, _ := range sbui.Bridges {
			d.torBridgeInternalType.Append(transport, transport)
		}
	}
	if d.torBridgeCustom, err = getRadioButton(b, "torBridgeCustom"); err != nil {
		return err
	} else {
		d.torBridgeCustom.Connect("toggled", func() { d.onBridgeTypeChanged() })
	}
	if d.torBridgeCustomFrame, err = getFrame(b, "torBridgeCustomFrame"); err != nil {
		return err
	}
	if d.torBridgeCustomEntry, err = getTextView(b, "torBridgeCustomEntry"); err != nil {
		return err
	}
	if _, err = d.torBridgeCustomEntry.GetProperty("monospace"); err == nil { // Gtk+ >= 3.16
		d.torBridgeCustomEntry.SetProperty("monospace", true)
	}
	if d.torBridgeCustomEntryBuf, err = d.torBridgeCustomEntry.GetBuffer(); err != nil {
		return err
	}
	if d.entryInsensitive, err = gtk3.TextTagNew("insensitive"); err != nil {
		return err
	} else {
		// XXX: Query this from the style somehow?
		d.entryInsensitive.SetProperty("foreground", "#878787")
		tt, err := d.torBridgeCustomEntryBuf.GetTagTable()
		if err != nil {
			return err
		}
		tt.Add(d.entryInsensitive)
	}

	// Sandbox config elements.
	if d.pulseAudioSwitch, err = getSwitch(b, "pulseAudioSwitch"); err != nil {
		return err
	}
	if d.avCodecSwitch, err = getSwitch(b, "avCodecSwitch"); err != nil {
		return err
	}
	if d.circuitDisplaySwitch, err = getSwitch(b, "circuitDisplaySwitch"); err != nil {
		return err
	}
	if d.amnesiacProfileSwitch, err = getSwitch(b, "amnesiacProfileSwitch"); err != nil {
		return err
	}
	if d.amnesiacProfileBox, err = getBox(b, "amnesiacProfileBox"); err != nil {
		return err
	}
	if d.displayBox, err = getBox(b, "displayBox"); err != nil {
		return err
	}
	if d.displayEntry, err = getEntry(b, "displayEntry"); err != nil {
		return err
	}
	if d.downloadsDirBox, err = getBox(b, "downloadsDirBox"); err != nil {
		return err
	}
	if d.downloadsDirChooser, err = getFChooser(b, "downloadsDirChooser"); err != nil {
		return err
	}
	if d.desktopDirBox, err = getBox(b, "desktopDirBox"); err != nil {
		return err
	}
	if d.desktopDirChooser, err = getFChooser(b, "desktopDirChooser"); err != nil {
		return err
	}

	ui.configDialog = d
	return nil
}
