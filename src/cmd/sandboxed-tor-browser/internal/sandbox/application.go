// application.go - Tor Browser sandbox launch routines.
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

// Package sandbox handles launching applications in a sandboxed enviornment
// via bubblwrap.
package sandbox

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"cmd/sandboxed-tor-browser/internal/dynlib"
	. "cmd/sandboxed-tor-browser/internal/sandbox/process"
	"cmd/sandboxed-tor-browser/internal/sandbox/x11"
	"cmd/sandboxed-tor-browser/internal/tor"
	"cmd/sandboxed-tor-browser/internal/ui/config"
	. "cmd/sandboxed-tor-browser/internal/utils"
)

const restrictedLibDir = "/usr/lib"

var distributionDependentLibSearchPath []string

// RunTorBrowser launches sandboxed Tor Browser.
func RunTorBrowser(cfg *config.Config, manif *config.Manifest, tor *tor.Tor) (process *Process, err error) {
	const (
		profileSubDir = "TorBrowser/Data/Browser/profile.default"
		cachesSubDir  = "TorBrowser/Data/Browser/Caches"
		stubPath      = "/home/amnesia/.tbb_stub.so"
		controlSocket = "control"
		socksSocket   = "socks"
		x11Socket     = "xorg"
	)

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	h, err := newHugbox()
	if err != nil {
		return nil, err
	}

	logger := newConsoleLogger("firefox")
	h.stdout = logger
	h.stderr = logger
	h.seccompFn = installTorBrowserSeccompProfile
	h.fakeDbus = true
	if manif.BundleVersionAtLeast("8.0a9") {
		h.mountProc = true //FF 60ESR needs this for now
	}
	h.fakeProc = false //FF 60ESR doesnt need this

	if manif.Channel == "alpha" && !manif.BundleVersionAtLeast("7.5a4") {
		// SelfRando prior to c619441e1ceec3599bc81bf9bbaf4d17c68b54b7 has a
		// bug in how it handles system call return values, leading to a
		// infinite loop if `/proc/self/environ` doesn't exist.
		//
		// Despite the fix for this being available upstream, the browser
		// people didn't pull it in for the 7.5a3 release.
		//
		// See: https://trac.torproject.org/projects/tor/ticket/22853
		Debugf("sandbox: SelfRando /proc/self/environ workaround enabled")
		h.file("/proc/self/environ", []byte{})
	}

	// Gtk+ and PulseAudio.
	hasAdwaita := h.appendGtk2Theme()
	h.roBind("/usr/share/icons/hicolor", "/usr/share/icons/hicolor", true)
	h.roBind("/usr/share/mime", "/usr/share/mime", false)

	pulseAudioWorks := false
	if cfg.Sandbox.EnablePulseAudio {
		if err = h.enablePulseAudio(); err != nil {
			log.Printf("sandbox: failed to proxy PulseAudio: %v", err)
		} else {
			pulseAudioWorks = true
		}
	}
	h.roBind("/usr/share/libthai/thbrk.tri", "/usr/share/libthai/thbrk.tri", true) // Thai language support (Optional).

	browserHome := filepath.Join(h.homeDir, "sandboxed-tor-browser", "tor-browser", "Browser")
	realBrowserHome := filepath.Join(cfg.BundleInstallDir, "Browser")
	realCachesDir := filepath.Join(realBrowserHome, cachesSubDir)
	realProfileDir := filepath.Join(realBrowserHome, profileSubDir)
	realDesktopDir := filepath.Join(realBrowserHome, "Desktop")
	realDownloadsDir := filepath.Join(realBrowserHome, "Downloads")
	realExtensionsDir := filepath.Join(realProfileDir, "extensions")

	// Ensure that the `Caches`, `Downloads` and `Desktop` mount points exist.
	if err = os.MkdirAll(realCachesDir, DirMode); err != nil {
		return
	}
	if err = os.MkdirAll(realDesktopDir, DirMode); err != nil {
		return
	}
	if err = os.MkdirAll(realDownloadsDir, DirMode); err != nil {
		return
	}

	// Apply directory overrides.
	if cfg.Sandbox.DesktopDir != "" {
		realDesktopDir = cfg.Sandbox.DesktopDir
	}
	if cfg.Sandbox.DownloadsDir != "" {
		realDownloadsDir = cfg.Sandbox.DownloadsDir
	}

	profileDir := filepath.Join(browserHome, profileSubDir)
	cachesDir := filepath.Join(browserHome, cachesSubDir)
	downloadsDir := filepath.Join(browserHome, "Downloads")
	desktopDir := filepath.Join(browserHome, "Desktop")
	extensionsDir := filepath.Join(profileDir, "extensions")

	prefFile := "preferences"
	prefFileOptional := false
	if manif.BundleVersionAtLeast("8.0a9") {
		//FF60
		prefFile = "prefs.js"
		prefFileOptional = true

		//AVANIX added this, 60ESR needs this schemas...
		//Enable Glib schemas to allow open, save etc...
		//GENERAL for all
		h.roBind("/usr/share/glib-2.0/schemas", "/usr/share/glib-2.0/schemas", false)
		//TODO: Fine control
		//h.roBind("/usr/share/glib-2.0/schemas/org.gtk.Settings.FileChooser.gschema.xml", "/usr/share/glib-2.0/schemas/org.gtk.Settings.FileChooser.gschema.xml", false)

		//Allow this for some icons
		h.roBind("/usr/share/icons/gnome", "/usr/share/icons/gnome", true)
	}

	// Filesystem stuff.
	h.roBind(cfg.BundleInstallDir, filepath.Join(h.homeDir, "sandboxed-tor-browser", "tor-browser"), false)

	if cfg.Sandbox.EnableAmnesiacProfileDirectory {
		excludes := []string{
			filepath.Join(realProfileDir, prefFile),
			realExtensionsDir,
		}
		h.shadowDir(profileDir, realProfileDir, excludes)
	} else {
		h.bind(realProfileDir, profileDir, false)
	}
	h.roBind(filepath.Join(realProfileDir, prefFile), filepath.Join(profileDir, prefFile), prefFileOptional)
	h.bind(realDesktopDir, desktopDir, false)
	h.bind(realDownloadsDir, downloadsDir, false)
	h.tmpfs(cachesDir)
	h.chdir = browserHome

	// Explicitly bind mount the expected extensions in.
	//
	// If the Tor Browser developers ever decide to do something sensible like
	// sign their XPI files, then the whitelist could be public key based, till
	// then this may be somewhat fragile.
	h.tmpfs(extensionsDir)
	for _, extName := range []string{
		"{73a6fe31-595d-460b-a920-fcc0f8843232}.xpi", // NoScript
		"torbutton@torproject.org.xpi",
		"https-everywhere-eff@eff.org.xpi",
		"tor-launcher@torproject.org.xpi",
	} {
		h.roBind(filepath.Join(realExtensionsDir, extName), filepath.Join(extensionsDir, extName), false)
	}

	// Env vars taken from start-tor-browser.
	// h.setenv("LD_LIBRARY_PATH", filepath.Join(browserHome, "TorBrowser", "Tor"))
	h.setenv("FONTCONFIG_PATH", filepath.Join(browserHome, "TorBrowser", "Data", "fontconfig"))
	h.setenv("FONTCONFIG_FILE", "fonts.conf")

	// This used to be for `hardened` but may eventually be required for
	// `alpha`, though according to trac, newer versions of selfrando fix the
	// problem.
	//
	// https://trac.torproject.org/projects/tor/ticket/20683#comment:13
	//
	// if manif.Channel == "alpha" {
	//	h.setenv("NSS_DISABLE_HW_AES", "1") // For selfrando.
	// }

	// GNOME systems will puke with a read-only home, so instead of setting
	// $HOME to point to inside the browser bundle, setup a bunch of
	// symlinks.
	//
	// `XDG_[DOWNLOAD,DESKTOP]_DIR` appear to be honored if they are in
	// `~/.config/user-dirs.dirs`, but are ignored if specified as env
	// vars.  The symlink approach is probably more user friendly anyway.
	//
	// h.setenv("HOME", browserHome)
	h.symlink(desktopDir, "/home/amnesia/Desktop")
	h.symlink(downloadsDir, "/home/amnesia/Downloads")

	// Set the same env vars that Tor Browser would expect when using a system
	// tor, since the launcher is responsible for managing the Tor process, and
	// it will be talking to the surrogates anyway.
	h.setenv("TOR_SOCKS_PORT", "9150")
	h.setenv("TOR_CONTROL_PORT", "9151")
	h.setenv("TOR_SKIP_LAUNCH", "1")
	h.setenv("TOR_NO_DISPLAY_NETWORK_SETTINGS", "1")
	h.setenv("TOR_HIDE_UPDATE_CHECK_UI", "1")

	// Inject the AF_LOCAL compatibility hack stub into the filesystem, and
	// supply the relevant args required for functionality.
	ctrlPath := filepath.Join(h.runtimeDir, controlSocket)
	socksPath := filepath.Join(h.runtimeDir, socksSocket)
	h.setenv("TOR_STUB_CONTROL_SOCKET", ctrlPath)
	h.setenv("TOR_STUB_SOCKS_SOCKET", socksPath)
	h.bind(tor.CtrlSurrogatePath(), ctrlPath, false)
	h.bind(tor.SocksSurrogatePath(), socksPath, false)
	h.assetFile(stubPath, "tbb_stub.so")

	ldPreload := stubPath
	h.setenv("LD_PRELOAD", ldPreload)

	// Hardware accelerated OpenGL will not work, and never will.
	h.setenv("LIBGL_ALWAYS_SOFTWARE", "1")

	// Crashdumps regardless of being sanitized or not, not to be trusted.
	h.setenv("MOZ_CRASHREPORTER_DISABLE", "1")

	// Tor Browser currently is incompatible with PaX MPROTECT, apply the
	// override if needed.
	realFirefoxPath := filepath.Join(realBrowserHome, "firefox")
	if manif.BundleVersionAtLeast("8.0a10") {
		realFirefoxPath = filepath.Join(realBrowserHome, "firefox.real")
	}
	needsPaXPaths := []string{
		realFirefoxPath,
		filepath.Join(realBrowserHome, "plugin-container"),
	}
	for _, p := range needsPaXPaths {
		err := applyPaXAttributes(manif, p)
		if err != nil {
			log.Printf("sandbox: Failed to apply PaX attributes to `%v`: %v", p, err)
		}
	}

	extraLdLibraryPath := ""
	if dynlib.IsSupported() {
		cache, err := dynlib.LoadCache()
		if err != nil {
			return nil, err
		}

		// XXX: It's probably safe to assume that firefox will always link
		// against libc and libpthread that are required by `tbb_stub.so`.
		binaries := []string{realFirefoxPath}
		matches, err := filepath.Glob(realBrowserHome + "/*.so")
		if err != nil {
			return nil, err
		}
		binaries = append(binaries, matches...)
		ldLibraryPath := realBrowserHome + ":" + filepath.Join(realBrowserHome, "TorBrowser", "Tor")

		// Extra libraries that firefox dlopen()s.
		extraLdLibraryPath = extraLdLibraryPath + ":" + restrictedLibDir
		extraLibs := []string{
			// These are absolutely required, or libxul.so will crash
			// the firefox process.  Perhapbs wayland will deliver us
			// from this evil.
			"libxcb.so.1",
			"libXau.so.6",
			"libXdmcp.so.6",

			// "libXss.so.1", - Not ubiquitous? nsIdleService uses this.
			// "libc.so", - Uhhhhh.... wtf?
			// "libcanberra.so.0", - Not ubiquitous.
		}

		glExtraLibs, glLibPaths := h.appendRestrictedOpenGL()
		extraLibs = append(extraLibs, glExtraLibs...)
		ldLibraryPath = ldLibraryPath + glLibPaths

		if cfg.Sandbox.EnablePulseAudio && pulseAudioWorks {
			paLibs, paPath, paExtraPath, err := h.appendRestrictedPulseAudio(cache)
			if err != nil {
				log.Printf("sandbox: Failed to find PulseAudio libraries: %v", err)
			} else {
				extraLibs = append(extraLibs, paLibs...)
				ldLibraryPath = ldLibraryPath + paPath
				extraLdLibraryPath = extraLdLibraryPath + paExtraPath
			}
		}

		allowFfmpeg := false
		if cfg.Sandbox.EnableAVCodec {
			if codec := findBestCodec(cache); codec != "" {
				extraLibs = append(extraLibs, codec)
				allowFfmpeg = true
			}
		}
		filterFn := func(fn string) error {
			return filterCodecs(fn, allowFfmpeg)
		}

		// Gtk uses plugin libraries and shit for theming, and expecting
		// them to be in consistent locations, is too much to ask for.
		gtkExtraLibs, gtkLibPaths, err := h.appendRestrictedGtk2(hasAdwaita)
		if err != nil {
			return nil, err
		}
		extraLibs = append(extraLibs, gtkExtraLibs...)
		ldLibraryPath = ldLibraryPath + gtkLibPaths

		if err := h.appendLibraries(cache, binaries, extraLibs, ldLibraryPath, filterFn); err != nil {
			return nil, err
		}
	}
	h.setenv("LD_LIBRARY_PATH", filepath.Join(browserHome, "TorBrowser", "Tor")+extraLdLibraryPath)

	h.cmd = filepath.Join(browserHome, "firefox")
	if manif.BundleVersionAtLeast("8.0a10") {
		h.cmd = filepath.Join(browserHome, "firefox.real")
	}
	h.cmdArgs = []string{"--class", "Tor Browser", "-profile", profileDir}

	// Do X11 last, because of the surrogate.
	x11SurrogatePath := filepath.Join(cfg.RuntimeDir, x11Socket)
	x, err := x11.New(cfg.Sandbox.Display, h.hostname, x11SurrogatePath)
	if err != nil {
		return nil, err
	} else {
		h.setenv("DISPLAY", x.Display)
		h.dir(x11.SockDir)
		if x.Xauthority != nil {
			xauthPath := filepath.Join(h.homeDir, ".Xauthority")
			h.setenv("XAUTHORITY", xauthPath)
			h.file(xauthPath, x.Xauthority)
		}
		if err = x.LaunchSurrogate(); err != nil {
			return nil, err
		}
		h.bind(x.Socket(), filepath.Join(x11.SockDir, "X0"), false)
	}
	x11TermHook := func() {
		if x.Surrogate != nil {
			Debugf("sandbox: X11: Cleaning up surrogate")
			x.Surrogate.Close()
		}
	}

	proc, err := h.run()
	if err != nil {
		x11TermHook()
		return nil, err
	} else {
		proc.AddTermHook(x11TermHook)
	}

	return proc, nil
}

func filterCodecs(fn string, allowFfmpeg bool) error {
	_, fn = filepath.Split(fn)
	lfn := strings.ToLower(fn)

	// Unless overridden, gstreamer is explicitly prohibited.
	codecPrefixes := []string{
		"libstreamer",
		"libgstapp",
		"libgstvideo",
	}
	if allowFfmpeg {
		codecPrefixes = []string{}
	} else if !allowFfmpeg {
		codecPrefixes = append(codecPrefixes, "libavcodec")
	}

	for _, prefix := range codecPrefixes {
		if strings.HasPrefix(lfn, prefix) {
			return fmt.Errorf("sandbox: Attempted to load AV codec when disabled: %v", fn)
		}
	}

	return nil
}

func findBestCodec(cache *dynlib.Cache) string {
	// This needs to be kept in sync with firefox. :(
	codecs := []string{
		"libavcodec-ffmpeg.so.57",
		"libavcodec-ffmpeg.so.56",
		"libavcodec.so.57",
		"libavcodec.so.56",
		"libavcodec.so.55",
		"libavcodec.so.54",
		"libavcodec.so.53",

		// Fairly sure upstream firefox is dropping support for these,
		// and NES emulators considered harmful.
		//
		// "libgstreamer-0.10.so.0",
		// "libgstapp-0.10.so.0",
		// "libgstvideo-0.10.so.0",
	}
	for _, codec := range codecs {
		if cache.GetLibraryPath(codec) != "" {
			return codec
		}
	}
	return ""
}

func applyPaXAttributes(manif *config.Manifest, f string) error {
	const paxAttr = "user.pax.flags"

	sz, _ := syscall.Getxattr(f, paxAttr, nil)
	_, n := filepath.Split(f)

	// Strip off the attribute if this is a non-grsec kernel.
	if !IsGrsecKernel() {
		if sz > 0 {
			log.Printf("sandbox: Removing PaX attributes: %v", n)
			syscall.Removexattr(f, paxAttr)
		}
		return nil
	}

	paxOverride := []byte{'m'}
	if sz > 0 {
		dest := make([]byte, sz)
		if _, err := syscall.Getxattr(f, paxAttr, dest); err != nil {
			return err
		}
		if bytes.Contains(dest, paxOverride) {
			log.Printf("sandbox: PaX attributes already set: %v", n)
			return nil
		}
	}

	log.Printf("sandbox: Applying PaX attributes: %v", n)
	return syscall.Setxattr(f, paxAttr, paxOverride, 0)
}

// RunUpdate launches sandboxed Tor Browser update.
func RunUpdate(cfg *config.Config, mar []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	h, err := newHugbox()
	if err != nil {
		return err
	}
	logger := newConsoleLogger("update")
	h.stdout = logger
	h.stderr = logger
	h.seccompFn = installTorBrowserSeccompProfile

	// https://wiki.mozilla.org/Software_Update:Manually_Installing_a_MAR_file
	const (
		installDir = "/home/amnesia/sandboxed-tor-browser/tor-browser"
		updateDir  = "/home/amnesia/sandboxed-tor-browser/update"
	)

	browserHome := filepath.Join(h.homeDir, "sandboxed-tor-browser", "tor-browser", "Browser")
	realInstallDir := cfg.BundleInstallDir
	realUpdateDir := filepath.Join(cfg.UserDataDir, "update")
	realUpdateBin := filepath.Join(realInstallDir, "Browser", "updater")

	// Do the work neccecary to make the firefox `updater` happy.
	if err = stageUpdate(realUpdateDir, realInstallDir, mar); err != nil {
		return err
	}

	h.bind(realInstallDir, installDir, false)
	h.bind(realUpdateDir, updateDir, false)
	h.chdir = browserHome // Required (Step 5.)

	extraLdLibraryPath := ""
	if dynlib.IsSupported() {
		cache, err := dynlib.LoadCache()
		if err != nil {
			return err
		}

		if err := h.appendLibraries(cache, []string{realUpdateBin}, nil, filepath.Join(realInstallDir, "Browser"), nil); err != nil {
			return err
		}
		extraLdLibraryPath = extraLdLibraryPath + ":" + restrictedLibDir
	}
	h.setenv("LD_LIBRARY_PATH", browserHome+extraLdLibraryPath)

	// 7. For Firefox 40.x and above run the following from the command prompto
	//    after adding the path to the existing installation directory to the
	//    LD_LIBRARY_PATH environment variable.
	h.cmd = filepath.Join(updateDir, "updater")
	h.cmdArgs = []string{updateDir, browserHome, browserHome}
	cmd, err := h.run()
	if err != nil {
		return err
	}
	cmd.Wait()

	// 8. After the update has completed a file named update.status will be
	//    created in the outside directory.
	status, err := ioutil.ReadFile(filepath.Join(realUpdateDir, "update.status"))
	if err != nil {
		return err
	}
	trimmedStatus := bytes.TrimSpace(status)
	if !bytes.Equal(trimmedStatus, []byte("succeeded")) {
		return fmt.Errorf("failed to apply update: %v", string(trimmedStatus))
	}

	// Since the update was successful, clean out the "outside" directory.
	os.RemoveAll(realUpdateDir)

	return nil
}

func stageUpdate(updateDir, installDir string, mar []byte) error {
	copyFile := func(src, dst string) error {
		// stat() the source file to get the file mode.
		fi, err := os.Lstat(src)
		if err != nil {
			return err
		}

		// Read the source file into memory.
		b, err := ioutil.ReadFile(src)
		if err != nil {
			return err
		}

		// Create and write the destination file.
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode())
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write(b)
		f.Sync()

		return err
	}

	// 1. Create a directory outside of the application's installation
	//    directory to be updated.
	if err := os.MkdirAll(updateDir, DirMode); err != nil {
		return err
	}

	// 2. Copy updater from the application's installation directory that is
	//    to be upgraded into the outside directory. If you would like to
	//    display the updater user interface while it is applying the update
	//    also copy the updater.ini into the outside directory.
	if err := copyFile(filepath.Join(installDir, "Browser", "updater"), filepath.Join(updateDir, "updater")); err != nil {
		return err
	}

	// 3. Download the appropriate .mar file and put it into the outside
	//    directory you created (see Where to get a mar file).
	// 4. Rename the mar file you downloaded to update.mar.
	if err := ioutil.WriteFile(filepath.Join(updateDir, "update.mar"), mar, FileMode); err != nil {
		return err
	}

	return nil
}

// RunTor launches sandboxeed Tor.
func RunTor(cfg *config.Config, manif *config.Manifest, torrc []byte) (process *Process, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	h, err := newHugbox()
	if err != nil {
		return nil, err
	}

	logger := newConsoleLogger("tor")
	h.stdout = logger
	h.stderr = logger
	h.seccompFn = func(fd *os.File) error { return installTorSeccompProfile(fd, cfg.Tor.UseBridges) }
	h.unshare.net = false // Tor needs host network access.

	// Regarding `/proc`...
	//
	// `/proc/meminfo` - tor daemon, used to calculate `MaxMemInQueues`,
	//    fails gracefully.
	// `/proc/sys/kernel/hostname` - obfs4proxy, Go runtime uses this to
	//    determine hostname, 99% sure this is in the binary but not used
	//    due to the `log` package's syslog target.
	// `/proc/sys/net/core/somaxconn` - obfs4proxy, Go runtime uses this to
	//    determine listener backlog, but will default to `128` on errors.
	//
	// `/proc/self/maps` - ASAN.  If it's ever enabled again, this mandates
	//    `/proc`.
	//
	// See: https://bugs.torproject.org/20773
	h.mountProc = false

	if err = os.MkdirAll(cfg.TorDataDir, DirMode); err != nil {
		return
	}

	realTorHome := filepath.Join(cfg.BundleInstallDir, "Browser", "TorBrowser", "Tor")
	realTorBin := filepath.Join(realTorHome, "tor")
	realGeoIPDir := filepath.Join(cfg.BundleInstallDir, "Browser", "TorBrowser", "Data", "Tor")
	torDir := filepath.Join(h.homeDir, "tor")
	torBinDir := filepath.Join(torDir, "bin")
	torrcPath := filepath.Join(torDir, "etc", "torrc")

	h.dir(torDir)
	h.roBind(realTorHome, torBinDir, false)
	for _, v := range []string{"geoip", "geoip6"} {
		h.roBind(filepath.Join(realGeoIPDir, v), filepath.Join(torDir, "etc", v), false)
	}
	h.bind(cfg.TorDataDir, filepath.Join(torDir, "data"), false)
	h.file(torrcPath, torrc)

	// If we have the dynamic linker cache available, only load in the
	// libraries that matter.
	extraLdLibraryPath := ""
	if dynlib.IsSupported() {
		cache, err := dynlib.LoadCache()
		if err != nil {
			return nil, err
		}

		// XXX: For now assume that PTs will always use a subset of the tor
		// binaries libraries.
		if err := h.appendLibraries(cache, []string{realTorBin}, nil, realTorHome, nil); err != nil {
			return nil, err
		}
		extraLdLibraryPath = extraLdLibraryPath + ":" + restrictedLibDir
	}
	h.setenv("LD_LIBRARY_PATH", torBinDir+extraLdLibraryPath)

	h.cmd = filepath.Join(torBinDir, "tor")
	h.cmdArgs = []string{"-f", torrcPath}

	return h.run()
}

type consoleLogger struct {
	prefix string
}

func (l *consoleLogger) Write(p []byte) (n int, err error) {
	for _, s := range bytes.Split(p, []byte{'\n'}) {
		if len(s) != 0 { // Trim empty lines.
			log.Printf("%s: %s", l.prefix, s)
		}
	}
	return len(p), nil
}

func newConsoleLogger(prefix string) *consoleLogger {
	l := new(consoleLogger)
	l.prefix = prefix
	return l
}

func findDistributionDependentLibs(extraSearch []string, subDir, fn string) string {
	var searchPaths []string
	searchPaths = append(searchPaths, extraSearch...)
	searchPaths = append(searchPaths, distributionDependentLibSearchPath...)

	for _, base := range searchPaths {
		candidate := filepath.Join(base, subDir, fn)
		if FileExists(candidate) && dynlib.ValidateLibraryClass(candidate) == nil {
			return candidate
		}
	}
	return ""
}

func findDistributionDependentDir(extraSearch []string, subDir, fn string) string {
	var searchPaths []string
	searchPaths = append(searchPaths, extraSearch...)
	searchPaths = append(searchPaths, distributionDependentLibSearchPath...)

	for _, base := range searchPaths {
		candidate := filepath.Join(base, subDir, fn)
		if DirExists(candidate) {
			return candidate
		}
	}
	return ""
}

func (h *hugbox) appendRestrictedOpenGL() ([]string, string) {
	const (
		archXorgDir = "/usr/lib/xorg/modules"
		swrastDri   = "swrast_dri.so"
	)

	swrastPath := findDistributionDependentLibs([]string{archXorgDir}, "dri", swrastDri)
	if swrastPath != "" {
		// Debian needs libGL.so.1 explicitly specified.
		retLibs := []string{swrastDri, "libGL.so.1"}

		driDir, _ := filepath.Split(swrastPath)
		restrictedDriDir := filepath.Join(restrictedLibDir, "dri")
		h.roBind(swrastPath, filepath.Join(restrictedDriDir, swrastDri), false)
		h.setenv("LIBGL_DRIVERS_PATH", restrictedDriDir)

		return retLibs, ":" + driDir
	}

	return nil, ""
}

func (h *hugbox) appendGtk2Theme() bool {
	const (
		themeDir          = "/usr/share/themes/Adwaita/gtk-2.0"
		iconDir           = "/usr/share/themes/Adwaita"
		adwaitaGtkrcAsset = "gtkrc-2.0"

		fallbackGtkrcAsset = "gtkrc-2.0-fallback"
	)

	gtkRc := fallbackGtkrcAsset

	hasAdwaita := DirExists(themeDir) && DirExists(iconDir)
	if hasAdwaita {
		h.roBind("/usr/share/themes/Adwaita/gtk-2.0", "/usr/share/themes/Adwaita/gtk-2.0", false)
		h.roBind("/usr/share/icons/Adwaita", "/usr/share/icons/Adwaita", false)
		gtkRc = adwaitaGtkrcAsset
	} else {
		log.Printf("sandbox: Failed to find Adwaita gtk-2.0 theme.")
	}

	gtkRcPath := filepath.Join(h.homeDir, ".gtkrc-2.0")
	h.setenv("GTK2_RC_FILES", gtkRcPath)
	h.assetFile(gtkRcPath, gtkRc)

	return hasAdwaita
}

func (h *hugbox) appendRestrictedGtk2(hasAdwaita bool) ([]string, string, error) {
	const (
		libAdwaita   = "libadwaita.so"
		libPixmap    = "libpixmap.so"
		libPngLoader = "libpixbufloader-png.so"
		libPrintFile = "libprintbackend-file.so"

		engineSubDir = "gtk-2.0/2.10.0/engines"
		printSubDir  = "gtk-2.0/2.10.0/printbackends"
		gdkSubDir    = "gdk-pixbuf-2.0/2.10.0/loaders"
	)

	gtkLibs := []string{}
	gtkLibPath := ""
	setGtkPath := false

	normGtkDir := filepath.Join(restrictedLibDir, "gtk-2.0", "2.10.0")

	// Figure out where the system keeps the Gtk+-2.0 theme libraries,
	// and bind mount in Adwaita and Pixmap.
	if hasAdwaita {
		adwaitaPath := findDistributionDependentLibs(nil, engineSubDir, libAdwaita)
		if adwaitaPath != "" {
			gtkEngineDir, _ := filepath.Split(adwaitaPath)
			normGtkEngineDir := filepath.Join(normGtkDir, "engines")
			h.roBind(adwaitaPath, filepath.Join(normGtkEngineDir, libAdwaita), false)
			h.roBind(filepath.Join(gtkEngineDir, libPixmap), filepath.Join(normGtkEngineDir, libPixmap), true)

			setGtkPath = true
			gtkLibs = append(gtkLibs, libAdwaita)
			gtkLibPath = gtkLibPath + ":" + gtkEngineDir
		} else {
			log.Printf("sandbox: Failed to find gtk-2.0 libadwaita.so.")
		}
	}

	// Figure out where the system keeps the Gtk+-2.0 print backends,
	// and bind mount in the file one.
	printFilePath := findDistributionDependentLibs(nil, printSubDir, libPrintFile)
	if printFilePath != "" {
		gtkPrintDir, _ := filepath.Split(printFilePath)
		normGtkPrintDir := filepath.Join(normGtkDir, "printbackends")
		h.roBind(printFilePath, filepath.Join(normGtkPrintDir, libPrintFile), false)

		setGtkPath = true
		gtkLibs = append(gtkLibs, libPrintFile)
		gtkLibPath = gtkLibPath + ":" + gtkPrintDir
	} else {
		log.Printf("sandbox: Failed to find gtk-2.0 libprintbackend-file.so.")
	}

	if setGtkPath {
		h.setenv("GTK_PATH", filepath.Join(restrictedLibDir, "gtk-2.0"))
	}

	// Figure out if the system gdk-pixbuf-2.0 needs loaders for common
	// file formats.  Arch and Fedora 25 do not.  Debian does.  As far as
	// I can tell, the only file format we actually care about is PNG.
	normGdkDir := filepath.Join(restrictedLibDir, "gdk-pixbuf-2.0", "2.10.0")
	pngLoaderPath := findDistributionDependentLibs(nil, gdkSubDir, libPngLoader)
	if pngLoaderPath != "" {
		loaderDir, _ := filepath.Split(pngLoaderPath)
		normPngLoaderPath := filepath.Join(normGdkDir, "loaders", libPngLoader)
		h.roBind(pngLoaderPath, normPngLoaderPath, false)

		loaderCachePath := filepath.Join(normGdkDir, "loaders.cache")
		h.assetFile(loaderCachePath, "loaders.cache")
		h.setenv("GDK_PIXBUF_MODULE_FILE", loaderCachePath)

		gtkLibs = append(gtkLibs, libPngLoader)
		gtkLibPath = gtkLibPath + ":" + loaderDir
	} else {
		// gdk-pixbuf can display an annoying warning if, it thinks it should
		// have a `loaders.cache` but doesnot.  Shut it up.
		h.setenv("GDK_PIXBUF_MODULE_FILE", "/dev/null")
	}

	// Bug #22712 - Spurious AT-SPI warnings.
	//
	// The Accessibility subsystem uses a subsystem via D-Bus to function,
	// and will warn if said subsystem is inaccessible.  As the host D-Bus
	// is not, and likely will never be accesible from within the container,
	// attempt to suppress the warnings.
	h.setenv("NO_AT_BRIDGE", "yes")

	return gtkLibs, gtkLibPath, nil
}

func (h *hugbox) appendLibraries(cache *dynlib.Cache, binaries []string, extraLibs []string, ldLibraryPath string, filterFn dynlib.FilterFunc) error {
	defer runtime.GC()

	// ld-linux(-x86-64).so needs special handling since it needs to be in
	// a precise location on the filesystem.
	ldSoPath, ldSoAlias, err := dynlib.FindLdSo(cache)
	if err != nil {
		Debugf("sandbox error dynlin.FindLdSo: %v", err)
		return err
	} else {
		Debugf("sandbox: ld.so appears to be '%v' -> %v.", ldSoAlias, ldSoPath)

		// Normalize.
		_, ldSoAliasFn := filepath.Split(ldSoAlias)
		ldSoAlias = filepath.Join("/lib", ldSoAliasFn)
	}

	// Search the distribution specific directories as well.
	fallbackLibSearchPath := strings.Join(distributionDependentLibSearchPath, fmt.Sprintf("%c", filepath.ListSeparator))
	toBindMount, err := cache.ResolveLibraries(binaries, extraLibs, ldLibraryPath, fallbackLibSearchPath, filterFn)
	if err != nil {
		Debugf("sandbox error cache.ResolveLibraries: %v", err)
		return err
	}

	// XXX: This needs one more de-dup pass to see if the sandbox expects two
	// different versions to share an alias.

	// Ensure that bindMounts happen in a consistent order.
	sortedLibs := []string{}
	for k, _ := range toBindMount {
		sortedLibs = append(sortedLibs, k)
	}
	sort.Strings(sortedLibs)

	// Append all the things!
	for _, realLib := range sortedLibs {
		if realLib == ldSoPath { // Special handling.
			h.roBind(realLib, ldSoAlias, false)
			continue
		}

		aliases := toBindMount[realLib]
		Debugf("sandbox: lib: %v", realLib)
		sort.Strings(aliases) // Likewise, ensure symlink ordering.

		// Avoid leaking information about exact library versions to cursory
		// inspection by bind mounting libraries in as the first alias, and
		// then symlinking off that.
		src := filepath.Join(restrictedLibDir, aliases[0])
		h.roBind(realLib, src, false)
		aliases = aliases[1:]
		if len(aliases) == 0 {
			continue
		}

		symlinked := make(map[string]bool) // XXX: Fairly sure this is unneeded.
		for _, alias := range aliases {
			dst := filepath.Join(restrictedLibDir, alias)
			if _, ok := symlinked[dst]; !ok {
				if dst != src {
					h.symlink(src, dst)
					symlinked[dst] = true
				}
			}
		}
	}

	// Some systems are really stubborn about searching for certain things
	// in the qualified lib directories.  In particular ld-linux.so needs to
	// be in exactly the right place, and openSUSE seems to really want to
	// use "/usr/lib64" for certain things.
	switch runtime.GOARCH {
	case "amd64":
		h.symlink("/lib", "/lib64")
		h.symlink(restrictedLibDir, "/usr/lib64")
	default:
		panic("sandbox: unsupported architecture: " + runtime.GOARCH)
	}

	h.standardLibs = false

	return nil
}

func init() {
	searchPaths := []string{
		"/usr/lib", // Arch Linux.
	}
	switch runtime.GOARCH {
	case "amd64":
		searchPaths = append([]string{
			"/usr/lib64",                // Fedora 25
			"/usr/lib/x86_64-linux-gnu", // Debian
		}, searchPaths...)
	default:
		panic("sandbox: unsupported architecture: " + runtime.GOARCH)
	}

	distributionDependentLibSearchPath = searchPaths
}
