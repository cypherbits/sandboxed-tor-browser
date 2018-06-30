// hugbox.go - Sandbox enviornment.
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

package sandbox

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cmd/sandboxed-tor-browser/internal/data"
	. "cmd/sandboxed-tor-browser/internal/sandbox/process"
	. "cmd/sandboxed-tor-browser/internal/utils"
)

type unshareOpts struct {
	user   bool
	ipc    bool
	pid    bool
	net    bool
	uts    bool
	cgroup bool
}

func (u *unshareOpts) toArgs() []string {
	var args []string

	if u.user {
		args = append(args, "--unshare-user")
	}
	if u.ipc {
		args = append(args, "--unshare-ipc")
	}
	if u.pid {
		args = append(args, "--unshare-pid")
	} else {
		// This is basically required for cleanup.
		panic("sandbox: unshare.pid is required")
	}
	if u.net {
		args = append(args, "--unshare-net")
	}
	if u.uts {
		args = append(args, "--unshare-uts")
	}
	if u.cgroup {
		args = append(args, "--unshare-cgroup-try")
	}
	return args
}

type hugbox struct {
	cmd     string
	cmdArgs []string

	hostname  string
	homeDir   string
	chdir     string
	mountProc bool
	fakeProc  bool
	unshare   unshareOpts
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
	seccompFn func(*os.File) error
	pdeathSig syscall.Signal

	fakeDbus     bool
	standardLibs bool

	// Internal options, not to be *modified* except via helpers, unless you
	// know what you are doing.
	bwrapPath    string
	bwrapVersion *bwrapVersion
	args         []string
	fileData     [][]byte

	runtimeDir string // Set at creation time.
}

func (h *hugbox) setenv(k, v string) {
	h.args = append(h.args, "--setenv", k, v)
}

func (h *hugbox) dir(dest string) {
	h.args = append(h.args, "--dir", dest)
}

func (h *hugbox) symlink(src, dest string) {
	h.args = append(h.args, "--symlink", src, dest)
}

func (h *hugbox) bind(src, dest string, optional bool) {
	if !FileExists(src) {
		if !optional {
			panic(fmt.Errorf("sandbox: bind source does not exist: %v", src))
		}
		return
	}
	h.args = append(h.args, "--bind", src, dest)
}

func (h *hugbox) roBind(src, dest string, optional bool) {
	if !FileExists(src) {
		if !optional {
			panic(fmt.Errorf("sandbox: roBind source does not exist: %v", src))
		}
		return
	}
	h.args = append(h.args, "--ro-bind", src, dest)
}

func (h *hugbox) file(dest string, data []byte) {
	h.args = append(h.args, "--file", fmt.Sprintf("%d", 4+len(h.fileData)), dest)
	h.fileData = append(h.fileData, data)
}

func (h *hugbox) setupDbus() {
	const idPath = "/var/lib/dbus/machine-id"
	var fakeUUID [16]byte

	// That's the kind of thing an idiot would have on his luggage!
	for i := range fakeUUID {
		fakeUUID[i] = byte(i)
	}
	hexUUID := hex.EncodeToString(fakeUUID[:])
	h.file(idPath, []byte(hexUUID))
	h.symlink(idPath, "/etc/machine-id") // openSUSE again.
}

func (h *hugbox) assetFile(dest, asset string) {
	b, err := data.Asset(asset)
	if err != nil {
		panic(err)
	}
	h.file(dest, b)
}

func (h *hugbox) tmpfs(dest string) {
	h.args = append(h.args, "--tmpfs", dest)
}

func (h *hugbox) shadowDir(dest, src string, exclude []string) {
	Debugf("sandbox: shadowDir: %s -> %s", src, dest)

	excludeMap := make(map[string]bool)
	for _, s := range exclude {
		excludeMap[s] = true
	}

	shadowWalk := func(path string, info os.FileInfo, err error) error {
		if path == src {
			h.tmpfs(dest)
			return nil
		}

		isDir := info.IsDir()
		if excludeMap[path] {
			Debugf("sandbox: shadowDir: excluding '%s'", path)
			if isDir {
				return filepath.SkipDir
			}
			return nil
		}

		// Dealing with this is annoying, and it doesn't happen under
		// normal usage.
		const (
			modeIrregular  = os.ModeSymlink | os.ModeNamedPipe | os.ModeSocket | os.ModeDevice
			modeExecutable = 0111
		)
		mode := info.Mode()
		if mode&modeIrregular != 0 {
			Debugf("sandbox: shadowDir: '%s' irregular perm bits: %s", path, mode)
			return fmt.Errorf("sandbox: shadowDir: '%s' irregular perm bits: %s", path, mode)
		} else if mode&modeExecutable != 0 && !isDir {
			// Alas shadowDir has limits, because bwrap doesn't give a easy way
			// to set this up.
			Debugf("sandbox: shadowDir: '%s' ignoring executable perm bits: %s", path, mode)
		}

		relPath := filepath.Clean(strings.TrimPrefix(path, src))
		destPath := filepath.Join(dest, relPath)
		if isDir {
			h.dir(destPath)
		} else {
			// XXX: This guzzles memory, and it'll be easier just to open
			// the source file, but cleanup on errors would be a huge
			// nightmare, because Go is too cool for destructors.
			b, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			h.file(destPath, b)
		}

		// Debugf("shadow: '%s' -> '%s'", relPath, destPath)

		return nil
	}

	// Create the directory, and then walk.
	if err := filepath.Walk(src, shadowWalk); err != nil {
		panic(err)
	}
}

func (h *hugbox) run() (*Process, error) {
	// Create the command struct for the sandbox.
	cmd := &exec.Cmd{
		Path:   h.bwrapPath,
		Args:   []string{h.bwrapPath, "--args", "3", h.cmd},
		Env:    []string{},
		Stdin:  h.stdin,
		Stdout: h.stdout,
		Stderr: h.stderr,
		SysProcAttr: &syscall.SysProcAttr{
			Setsid:    true,
			Pdeathsig: h.pdeathSig,
		},
	}
	cmd.Args = append(cmd.Args, h.cmdArgs...)

	defer func() {
		// Force close the unwritten pipe fd(s), on the off-chance that
		// something failed before they could be written.
		for _, f := range cmd.ExtraFiles {
			f.Close()
		}
	}()

	// Prep the args pipe.
	var argsWrFd *os.File
	if r, w, err := os.Pipe(); err != nil {
		return nil, err
	} else {
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		argsWrFd = w
	}

	// Build up the args to be passed via fd.  This specifies args directly
	// instead of using accessors since not everything is exposed, and
	// bubblewrap will fail if the assumptions I need to make about the
	// host system are false.
	fdArgs := []string{
		// Standard things required by most applications.
		"--dev", "/dev",
		"--tmpfs", "/tmp",

		"--setenv", "XDG_RUNTIME_DIR", h.runtimeDir,
		"--dir", h.runtimeDir,

		"--setenv", "HOME", h.homeDir,
		"--dir", h.homeDir,
	}
	if h.standardLibs {
		fdArgs = append(fdArgs, []string{
			"--ro-bind", "/usr/lib", "/usr/lib",
			"--ro-bind", "/lib", "/lib",
		}...)
		if runtime.GOARCH == "amd64" { // 64 bit Linux-ism.
			fdArgs = append(fdArgs, "--ro-bind", "/lib64", "/lib64")
			if FileExists("/usr/lib64") {
				// openSUSE keeps 64 bit libraries here.
				fdArgs = append(fdArgs, "--ro-bind", "/usr/lib64", "/usr/lib64")
			}
		}
	}
	fdArgs = append(fdArgs, h.unshare.toArgs()...) // unshare(2) options.
	if h.hostname != "" {
		if !h.unshare.uts {
			return nil, fmt.Errorf("sandbox: hostname set, without new UTS namespace")
		}
		fdArgs = append(fdArgs, "--hostname", h.hostname)
	}
	if h.mountProc {
		fdArgs = append(fdArgs, "--proc", "/proc")
	} else if h.fakeProc {
		// Firefox attempts to figure out if a given process is multithreaded
		// or not by stat(2)ing `/proc/self/task` and examining `st_nlink`.
		//
		// This error is harmless on most systems, but as of 7.0.7, will
		// totally break everything if `SECCOMP_FILTER_FLAG_TSYNC` is not
		// supported (Linux < 3.17).
		fdArgs = append(fdArgs, "--dir", "/proc/self/task/fakeProc")
	}
	if h.chdir != "" {
		fdArgs = append(fdArgs, "--chdir", h.chdir)
	}

	uid, gid := os.Getuid(), os.Getgid()
	if h.unshare.user {
		uid, gid = 1000, 1000
		fdArgs = append(fdArgs, []string{
			"--uid", "1000",
			"--gid", "1000",
		}...)
	}
	passwdBody := fmt.Sprintf("amnesia:x:%d:%d:Debian Live User,,,:/home/amnesia:/bin/bash\n", uid, gid)
	groupBody := fmt.Sprintf("amnesia:x:%d:\n", gid)
	h.file("/etc/passwd", []byte(passwdBody))
	h.file("/etc/group", []byte(groupBody))

	dieWithParent := h.bwrapVersion.atLeast(0, 1, 8)
	if dieWithParent {
		Debugf("sandbox: bubblewrap supports `--die-with-parent`.")
		fdArgs = append(fdArgs, "--die-with-parent")
	}

	if h.fakeDbus {
		h.setupDbus()
	}

	// Handle the files to be injected via pipes.
	fdIdx := 4
	pendingWriteFds := []*os.File{argsWrFd}
	for i := 0; i < len(h.fileData); i++ {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		pendingWriteFds = append(pendingWriteFds, w)
		fdIdx++
	}

	// Prep the seccomp pipe if required.
	var seccompWrFd *os.File
	if h.seccompFn != nil {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		fdArgs = append(fdArgs, "--seccomp", fmt.Sprintf("%d", fdIdx))
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		seccompWrFd = w
		fdIdx++
	}

	// Prep the info pipe.
	var infoRdFd *os.File
	if r, w, err := os.Pipe(); err != nil {
		return nil, err
	} else {
		cmd.ExtraFiles = append(cmd.ExtraFiles, w)
		fdArgs = append(fdArgs, "--info-fd", fmt.Sprintf("%d", fdIdx))
		infoRdFd = r
	}

	// Convert the arg vector to a format fit for bubblewrap, and schedule the
	// write.
	fdArgs = append(fdArgs, h.args...) // Finalize args.
	var argsBuf []byte
	for _, arg := range fdArgs {
		argsBuf = append(argsBuf, []byte(arg)...)
		argsBuf = append(argsBuf, 0x00)
	}
	pendingWrites := [][]byte{argsBuf}
	pendingWrites = append(pendingWrites, h.fileData...)

	Debugf("sandbox: fdArgs: %v", fdArgs)

	// Fork/exec.
	cmd.Start()

	// Do the rest of the setup in a go routine, and monitor completion and
	// a watchdog timer.
	doneCh := make(chan error)
	hz := time.NewTicker(1 * time.Second)
	defer hz.Stop()

	process := NewProcess(cmd)

	go func() {
		// Flush the pending writes.
		for i, wrFd := range pendingWriteFds {
			d := pendingWrites[i]
			if err := writeBuffer(wrFd, d); err != nil {
				doneCh <- err
				return
			}
			cmd.ExtraFiles = cmd.ExtraFiles[1:]
		}

		// Write the seccomp rules.
		if h.seccompFn != nil {
			// This should be the one and only remaining extra file.
			if len(cmd.ExtraFiles) != 2 {
				panic("sandbox: unexpected extra files when writing seccomp rules")
			} else if seccompWrFd == nil {
				panic("sandbox: missing fd when writing seccomp rules")
			}
			if err := h.seccompFn(seccompWrFd); err != nil {
				doneCh <- err
				return
			}
			cmd.ExtraFiles = cmd.ExtraFiles[1:]
		} else if seccompWrFd != nil {
			panic("sandbox: seccomp fd exists when there are no rules to be written")
		}

		// Read back the init child pid.
		decoder := json.NewDecoder(infoRdFd)
		info := &bwrapInfo{}
		if err := decoder.Decode(info); err != nil {
			doneCh <- err
			return
		}

		Debugf("sandbox: bwrap pid is: %v", cmd.Process.Pid)
		Debugf("sandbox: bwrap init pid is: %v", info.Pid)

		// Sending a SIGKILL to this will terminate every process in the PID
		// namespace.  If people aren't using unshare.pid, bad things happen.
		process.SetInitPid(info.Pid)

		doneCh <- nil
	}()

	err := fmt.Errorf("sandbox: timeout waiting for bubblewrap to start")
timeoutLoop:
	for nTicks := 0; nTicks < 10; { // 10 second timeout, probably excessive.
		select {
		case err = <-doneCh:
			if err == nil {
				return process, nil
			}
			break timeoutLoop
		case <-hz.C:
			if !process.Running() {
				err = fmt.Errorf("sandbox: bubblewrap exited unexpectedly")
				break timeoutLoop
			}
			nTicks++
		}
	}

	process.Kill()
	return nil, err
}

type bwrapInfo struct {
	Pid int `json:"child-pid"`
}

func newHugbox() (*hugbox, error) {
	h := &hugbox{
		unshare: unshareOpts{
			user:   false,
			ipc:    true,
			pid:    true,
			net:    true,
			uts:    true,
			cgroup: true,
		},
		hostname:     "amnesia",
		mountProc:    true,
		runtimeDir:   filepath.Join("/run", "user", fmt.Sprintf("%d", os.Getuid())),
		homeDir:      "/home/amnesia",
		pdeathSig:    syscall.SIGTERM,
		standardLibs: true,
	}

	// This option is considered dangerous and leads to things like
	// CVE-2016-8655.  But if the user is running with this enabled,
	// then might as well take advantage of it.
	if FileExists("/proc/self/ns/user") {
		Debugf("sandbox: User namespace support detected.")
		h.unshare.user = true
		h.runtimeDir = "/run/user/1000"
	}

	// Look for the bwrap binary in sensible locations.
	bwrapPaths := []string{
		"/usr/bin/bwrap",
	}
	for _, v := range bwrapPaths {
		if FileExists(v) {
			h.bwrapPath = v
			break
		}
	}
	if h.bwrapPath == "" {
		return nil, fmt.Errorf("sandbox: unable to find bubblewrap binary")
	}

	// Query and cache the bubblewrap version.
	var err error
	if h.bwrapVersion, err = getBwrapVersion(h.bwrapPath); err != nil {
		return nil, err
	} else {
		Debugf("sandbox: bubblewrap '%v' detected.", h.bwrapVersion)

		// Bubblewrap <= 0.1.2-2 (in Debian terms, 0.1.3 for the rest of us),
		// is a really bad idea because I'm a retard, and didn't expect
		// bubblewrap to be ptrace-able when I contributed support for setting
		// the hostname.
		if !h.bwrapVersion.atLeast(0, 1, 3) {
			return nil, fmt.Errorf("sandbox: bubblewrap appears to be older than 0.1.3, you MUST upgrade.")
		}
	}

	return h, nil
}

type bwrapVersion struct {
	maj, min, pl int
}

func (v *bwrapVersion) atLeast(maj, min, pl int) bool {
	if v.maj > maj {
		return true
	}
	if v.maj == maj && v.min > min {
		return true
	}
	if v.maj == maj && v.min == min && v.pl >= pl {
		return true
	}
	return false
}

func (v *bwrapVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.maj, v.min, v.pl)
}

func getBwrapVersion(f string) (*bwrapVersion, error) {
	cmd := &exec.Cmd{
		Path: f,
		Args: []string{f, "--version"},
		Env:  []string{},
		SysProcAttr: &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGKILL,
		},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sandbox: failed to query bubblewrap version: %v", string(out))
	}
	vStr := strings.TrimPrefix(string(out), "bubblewrap ")
	vStr = strings.TrimSpace(vStr)

	// Split into major/minor/pl.
	v := strings.Split(vStr, ".")
	if len(v) < 3 {
		return nil, fmt.Errorf("unable to determine bubblewrap version")
	}

	// Parse the version.
	var iVers [3]int
	for i := 0; i < 3; i++ {
		iv, err := strconv.Atoi(v[i])
		if err != nil {
			return nil, fmt.Errorf("unable to parse bubblewrap version: %v", err)
		}
		iVers[i] = iv
	}

	return &bwrapVersion{maj: iVers[0], min: iVers[1], pl: iVers[2]}, nil
}

func writeBuffer(w io.WriteCloser, contents []byte) error {
	defer w.Close()
	_, err := w.Write(contents)
	return err
}

// IsGrsecKernel returns true if the system appears to be running a grsec
// kernel.
func IsGrsecKernel() bool {
	grsecFiles := []string{
		"/proc/sys/kernel/grsecurity",
		"/proc/sys/kernel/pax",
		"/dev/grsec",
	}
	for _, f := range grsecFiles {
		if FileExists(f) {
			return true
		}
	}
	return false
}
