// config.go - Configuration routines.
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

// Package config handles the launcher configuration.
package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	gonet "net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	butils "git.schwanenlied.me/yawning/bulb.git/utils"
	xdg "github.com/cep21/xdgbasedir"

	"cmd/sandboxed-tor-browser/internal/utils"
)

const (
	configFile   = "sandboxed-tor-browser.json"
	manifestFile = "manifest.json"

	defaultChannel = "release"
	defaultLocale  = "en-US"
	archLinux32    = "linux32"
	archLinux64    = "linux64"

	appDir           = "sandboxed-tor-browser"
	bundleInstallDir = "tor-browser"
	torDataDir       = "tor"
)

// TorProxyTypes are the proxy protocols supported by tor.
var TorProxyTypes = []string{"SOCKS 4", "SOCKS 5", "HTTP(S)"}

// Tor contains the Tor network config options.
type Tor struct {
	cfg *Config

	// CtrlPassword is the unhashed onctol port password.
	CtrlPassword string `json:"-"`

	// UseProxy is if the Tor network should be reached via a local proxy.
	UseProxy bool `json:"useProxy"`

	// ProxyType is the proxy protocol that should be used.
	ProxyType string `json:"proxyType"`

	// ProxyAddress is the proxy address that should be used.
	ProxyAddress string `json:"proxyAddress"`

	// ProxyPort is the proxy port that should be used.
	ProxyPort string `json:"proxyPort"`

	// ProxyUsername is the optional proxy username.
	ProxyUsername string `json:"proxyUsername"`

	// ProxyPassword is the optional proxy password.
	ProxyPassword string `json:"proxyPassword"`

	// UseBridges is if the Tor network should be reached via a bridge.
	UseBridges bool `json:"useBridges"`

	// InternalBridgeType is the bridge transport to use when using built in
	// bridges.
	InternalBridgeType string `json:"internalBridgeType"`

	// InternalBridgeSeed is the seed to use when permuting the internal
	// bridges for load balancing purposes.
	InternalBridgeSeed int64 `json:"internalBridgeSeed"`

	// UseCustomBridges is if the user provided bridges should be used.
	UseCustomBridges bool `json:"useCustomBridges"`

	// CustomBridges is the user provided bridge lines.
	CustomBridges string `json:"customBridges"`
}

// SetUseProxy sets if the Tor network should be reached via a local proxy and
// marks the config dirty.
func (t *Tor) SetUseProxy(b bool) {
	if t.UseProxy != b {
		t.UseProxy = b
		t.cfg.isDirty = true
	}
}

// SetProxyType sets the proxy protocol to be used by tor and marks the config
// dirty.
func (t *Tor) SetProxyType(s string) {
	if t.ProxyType != s {
		t.ProxyType = s
		t.cfg.isDirty = true
	}
}

// SetProxyAddress sets the proxy address to be used by tor and marks the
// config dirty.
func (t *Tor) SetProxyAddress(s string) {
	if t.ProxyAddress != s {
		t.ProxyAddress = s
		t.cfg.isDirty = true
	}
}

// SetProxyPort sets the proxy port to be used by tor and marks the config
// dirty.
func (t *Tor) SetProxyPort(s string) {
	if t.ProxyPort != s {
		t.ProxyPort = s
		t.cfg.isDirty = true
	}
}

// SetProxyUsername sets the proxy username to be used by tor and marks the
// config dirty.
func (t *Tor) SetProxyUsername(s string) {
	if t.ProxyUsername != s {
		t.ProxyUsername = s
		t.cfg.isDirty = true
	}
}

// SetProxyPassword sets the proxy password to be used by tor and marks the
// config dirty.
func (t *Tor) SetProxyPassword(s string) {
	if t.ProxyPassword != s {
		t.ProxyPassword = s
		t.cfg.isDirty = true
	}
}

// SetUseBridges sets if the Tor network should be reached via a Bridge and
// marks the config dirty.
func (t *Tor) SetUseBridges(b bool) {
	if t.UseBridges != b {
		t.UseBridges = b
		t.cfg.isDirty = true
	}
}

// SetInternalBridgeType sets the transport to be used when using built in
// bridges and marks the config dirty.
func (t *Tor) SetInternalBridgeType(s string) {
	if t.InternalBridgeType != s {
		t.InternalBridgeType = s
		t.cfg.isDirty = true
	}
}

// SetInternalBridgeSeed sets the seed to use when permuting the internal
// bridges for load balancing purposes and marks the config dirty.
func (t *Tor) SetInternalBridgeSeed(i int64) {
	if t.InternalBridgeSeed != i {
		t.InternalBridgeSeed = i
		t.cfg.isDirty = true
	}
}

// SetCustomBridges sets the user provided custom bridge lines, and maarks the
// config dirty.
func (t *Tor) SetCustomBridges(s string) {
	if t.CustomBridges != s {
		t.CustomBridges = s
		t.cfg.isDirty = true
	}
}

// SetUseCustomBridges sets if the user provided custom bridges should be used
// and marks the config dirty.
func (t *Tor) SetUseCustomBridges(b bool) {
	if t.UseCustomBridges != b {
		t.UseCustomBridges = b
		t.cfg.isDirty = true
	}
}

// Sandbox contains the sandbox specific config options.
type Sandbox struct {
	cfg *Config

	// Display is the X11 DISPLAY to use in the sandbox.  If omitted, the
	// host system DISPLAY from the env var will be used.
	Display string `json:"display,omitEmpty"`

	// EnablePulseAudio enables access to the host PulseAudio daemon inside the
	// sandbox.
	EnablePulseAudio bool `json:"enablePulseAudio"`

	// EnableAVCodec enables extra codecs via ffmpeg's libavcodec.so inside
	// the sandbox.
	EnableAVCodec bool `json:"enableAVCodec"`

	// EnableCircuitDisplay enables the Tor Browser circuit display.
	EnableCircuitDisplay bool `json:"enableCircuitDisplay"`

	// EnableAmnesiacProfileDirectory enables amnesiac profile directories.
	EnableAmnesiacProfileDirectory bool `json:"enableAmnesiacProfileDirectory"`

	// DesktopDir is the directory to be bind mounted instead of the default
	// bundle Desktop directory.
	DesktopDir string `json:"desktopDir,omitEmpty"`

	// DownloadsDir is the directory to be bind mounted instead of the default
	// bundle Downloads directory.
	DownloadsDir string `json:"downloadsDir,omitEmpty"`
}

// SetDisplay sets the sandbox `DISPLAY` override and marks the config dirty.
func (sb *Sandbox) SetDisplay(s string) {
	if sb.Display != s {
		sb.Display = s
		sb.cfg.isDirty = true
	}
}

// SetEnablePulseAudio sets the sandbox pulse audo enable and marks the config
// dirty.
func (sb *Sandbox) SetEnablePulseAudio(b bool) {
	if sb.EnablePulseAudio != b {
		sb.EnablePulseAudio = b
		sb.cfg.isDirty = true
	}
}

// SetEnableAVCodec sets the sandbox libavcodec enable and marks the config
// dirty.
func (sb *Sandbox) SetEnableAVCodec(b bool) {
	if sb.EnableAVCodec != b {
		sb.EnableAVCodec = b
		sb.cfg.isDirty = true
	}
}

// SetEnableCircuitDisplay sets the circit display enable and marks the config
// dirty.
func (sb *Sandbox) SetEnableCircuitDisplay(b bool) {
	if sb.EnableCircuitDisplay != b {
		sb.EnableCircuitDisplay = b
		sb.cfg.isDirty = true
	}
}

// SetEnableAmnesiacProfileDirectory sets the amnesiac profile directory enable
// and marks the config dirty.
func (sb *Sandbox) SetEnableAmnesiacProfileDirectory(b bool) {
	if sb.EnableAmnesiacProfileDirectory != b {
		sb.EnableAmnesiacProfileDirectory = b
		sb.cfg.isDirty = true
	}
}

// SetDownloadsDir sets the sandbox `~/Downloads` bind mount source and marks
// the config dirty.
func (sb *Sandbox) SetDownloadsDir(s string) {
	if sb.DownloadsDir != s {
		sb.DownloadsDir = s
		sb.cfg.isDirty = true
	}
}

// SetDesktopDir sets the sandbox `~/Desktop` bind mount source and marks the
// config dirty.
func (sb *Sandbox) SetDesktopDir(s string) {
	if sb.DesktopDir != s {
		sb.DesktopDir = s
		sb.cfg.isDirty = true
	}
}

// Config is the sandboxed-tor-browser configuration instance.
type Config struct {
	// Architecture is the current architecture derived at runtime ("linux32",
	// "linux64").
	Architecture string `json:"-"`

	// Channel is the Tor Browser channel to install ("release", "alpha")
	Channel string `json:"channel,omitempty"`

	// Locale is the Tor Browser locale to install ("en-US", "ja").
	Locale string `json:"locale,omitempty"`

	// LastUpdateCheck is the UNIX time when the last update check was
	// sucessfully completed.
	LastUpdateCheck int64 `json:"lastUpdateCheck,omitEmpty"`

	// ForceUpdate is set if the installed bundle is known to be obsolete.
	ForceUpdate bool `json:"forceUpdate"`

	// SkipPartialUpdate is set if the partial update has failed to apply.
	SkipPartialUpdate bool `json:"skipPartialUpdate"`

	// Tor is the Tor network configuration.
	Tor Tor `json:"tor,omitEmpty"`

	// Sandbox is the sandbox configuration.
	Sandbox Sandbox `json:"sandbox,omitEmpty"`

	// FirstLaunch is set for the first launch post install.
	FirstLaunch bool `json:"firstLaunch"`

	// LastVersion is the last `sandboxed-tor-browser` version that wrote
	// the config file.
	LastVersion string `json:"lastVersion"`

	// UseSystemTor indicates if a system tor daemon should be used.
	UseSystemTor bool `json:"-"`

	// SystemTorControlPort is the system tor daemon control port network.
	SystemTorControlNet string `json:"-"`

	// SystemTorControlAddr is the system tor daemon control port address.
	SystemTorControlAddr string `json:"-"`

	// RumtineDir is `$XDG_RUNTIME_DIR/appDir`.
	RuntimeDir string `json:"-"`

	// UserDataDir is `$XDG_USER_DATA_DIR/appDir`.
	UserDataDir string `json:"-"`

	// BundeInstallDir is `UserDataDir/bundleInstallDir`.
	BundleInstallDir string `json:"-"`

	// TorDataDir is `UserDataDir/torDataDir`.
	TorDataDir string `json:"-"`

	// ConfigDir is `XDG_CONFIG_HOME/appDir`.
	ConfigDir string `json:"-"`

	// ConfigVersionChanged indicates that the config file was from an old
	// version.
	ConfigVersionChanged bool `json:"-"`

	isDirty      bool
	path         string
	manifestPath string
}

// SetLocale sets the configured locale, and marks the config dirty.
func (cfg *Config) SetLocale(l string) {
	if l != cfg.Locale {
		cfg.isDirty = true
		cfg.Locale = l
	}
}

// SetChannel sets the configured channel, and marks the config dirty.
func (cfg *Config) SetChannel(c string) {
	if c != cfg.Channel {
		cfg.isDirty = true
		cfg.Channel = c
	}
}

// SetFirstLaunch sets the first launch flag and marks the config dirty.
func (cfg *Config) SetFirstLaunch(b bool) {
	if cfg.FirstLaunch != b {
		cfg.FirstLaunch = b
		cfg.isDirty = true
	}
}

// NeedsUpdateCheck returns true if the bundle needs to be checked for updates,
// and possibly updated.
func (cfg *Config) NeedsUpdateCheck() bool {
	const updateInterval = 60 * 60 * 2 // 2 hours, TBB behavior.
	now := time.Now().Unix()
	return (now > cfg.LastUpdateCheck+updateInterval) || cfg.LastUpdateCheck > now
}

// SetLastUpdateCheck sets the last update check time and marks the config
// dirty.
func (cfg *Config) SetLastUpdateCheck(t int64) {
	if cfg.LastUpdateCheck != t {
		cfg.LastUpdateCheck = t
		cfg.isDirty = true
	}
}

// SetForceUpdate sets the bundle as needed an update and marks the config
// dirty.
func (cfg *Config) SetForceUpdate(b bool) {
	if cfg.ForceUpdate != b {
		cfg.ForceUpdate = b
		cfg.isDirty = true
	}
}

// SetSkipPartailUpdate sets the bundle as needing a complete update as opposed
// to a partial one, and marks the config dirty.
func (cfg *Config) SetSkipPartialUpdate(b bool) {
	if cfg.SkipPartialUpdate != b {
		cfg.SkipPartialUpdate = b
		cfg.isDirty = true
	}
}

// Sanitize validates the config, and brings it inline with reality.
func (cfg *Config) Sanitize() {
	if !utils.DirExists(cfg.Sandbox.DownloadsDir) {
		cfg.Sandbox.SetDownloadsDir("")
	}
	if !utils.DirExists(cfg.Sandbox.DesktopDir) {
		cfg.Sandbox.SetDesktopDir("")
	}
}

// Sync flushes config changes to disk, if the config is dirty.
func (cfg *Config) Sync() error {
	if cfg.isDirty {
		// Encode to JSON and write to disk.
		if b, err := json.Marshal(&cfg); err != nil {
			return err
		} else if err = ioutil.WriteFile(cfg.path, b, utils.FileMode); err != nil {
			return err
		}

		cfg.isDirty = false
	}
	return nil
}

// ResetDirty resets the config's dirty flag, causing changes to be discarded on
// the Sync call.  This routine should only be used immediately prior to
// termination.
func (cfg *Config) ResetDirty() {
	cfg.isDirty = false
}

// New creates a new config object and populates it with the configuration
// from disk if available, default values otherwise.
func New(version string) (*Config, error) {
	const (
		envControlPort = "TOR_CONTROL_PORT"
		envRuntimeDir  = "XDG_RUNTIME_DIR"
	)

	cfg := new(Config)

	// Populate the internal only fields that are not serialized.
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("unsupported OS: %v", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "amd64":
		cfg.Architecture = archLinux64
	default:
		return nil, fmt.Errorf("unsupported Arch: %v", runtime.GOARCH)
	}
	if env := os.Getenv(envControlPort); env != "" {
		if net, addr, err := butils.ParseControlPortString(env); err != nil {
			return nil, fmt.Errorf("invalid control port: %v", err)
		} else {
			// Refuse to use TCP control ports not on the loopback interface.
			if net == "tcp" {
				host, _, _ := gonet.SplitHostPort(addr)
				if !gonet.ParseIP(host).IsLoopback() {
					return nil, fmt.Errorf("non-loopback control port: %v", host)
				}
			}
			cfg.UseSystemTor = true
			cfg.SystemTorControlNet = net
			cfg.SystemTorControlAddr = addr
		}
	}

	// Initialize the directories that have files in them.  The paths are not
	// serialized but part of the config struct.
	if d := os.Getenv(envRuntimeDir); d == "" {
		return nil, fmt.Errorf("no `%s` set in the enviornment", envRuntimeDir)
	} else {
		cfg.RuntimeDir = filepath.Join(d, appDir)
	}
	if d, err := xdg.DataHomeDirectory(); err != nil {
		return nil, err
	} else {
		cfg.UserDataDir = filepath.Join(d, appDir)
		cfg.BundleInstallDir = filepath.Join(cfg.UserDataDir, bundleInstallDir)
		cfg.TorDataDir = filepath.Join(cfg.UserDataDir, torDataDir)
		cfg.manifestPath = filepath.Join(cfg.UserDataDir, manifestFile)
	}

	// Ensure the path used to store the config file exits.
	if d, err := xdg.ConfigHomeDirectory(); err != nil {
		return nil, err
	} else {
		d = filepath.Join(d, appDir)
		if err := os.MkdirAll(d, utils.DirMode); err != nil {
			return nil, err
		}
		cfg.ConfigDir = d
		cfg.path = filepath.Join(cfg.ConfigDir, configFile)
	}

	// Load the config file.
	cfg.isDirty = true
	if b, err := ioutil.ReadFile(cfg.path); err != nil {
		// File not found, or failed to read.
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else if err = json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	} else if cfg.LastVersion != version {
		// The version changed, we want to re-Sync().
		cfg.LastVersion = version
		cfg.ConfigVersionChanged = true
	} else {
		cfg.isDirty = false
	}

	// Apply sensible defaults for unset items.
	if cfg.Channel == "" {
		cfg.SetChannel(defaultChannel)
	}
	if cfg.Locale == "" {
		cfg.SetLocale(defaultLocale)
	}
	cfg.Tor.cfg = cfg
	cfg.Sandbox.cfg = cfg

	return cfg, nil
}
