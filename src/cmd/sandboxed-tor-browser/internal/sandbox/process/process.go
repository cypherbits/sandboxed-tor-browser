// process.go - Sandboxed process.
// Copyright (C) 2017  Yawning Angel.
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

// Package process contains a wrapper around a running bwrap instance, and is
// in a separate package just to break an import loop.
package process

import (
	"os"
	"os/exec"
	"syscall"
)

// Process is a running bwrap instance.
type Process struct {
	init      *os.Process
	cmd       *exec.Cmd
	termHooks []func()
}

func (p *Process) onExit() {
	if p.termHooks != nil {
		for _, fn := range p.termHooks {
			fn()
		}
		p.termHooks = nil
	}
}

// AddTermHook adds the hook function fn to be called on process exit.
func (p *Process) AddTermHook(fn func()) {
	p.termHooks = append(p.termHooks, fn)
}

// Kill terminates the bwrap instance and all of it's children.
func (p *Process) Kill() {
	if p.init != nil {
		p.init.Kill()
		p.init = nil
	}
	if p.cmd != nil {
		p.cmd.Process.Kill()
		p.cmd.Process.Wait()
		p.cmd = nil
	}
	p.onExit()
}

// Wait waits for the bwrap instance to complete.
func (p *Process) Wait() error {
	// Can't wait on the init process since it's a grandchild.
	if p.cmd != nil {
		p.cmd.Process.Wait()
		p.cmd = nil
		p.onExit()
	}
	return nil
}

// Running returns true if the bwrap instance is running.
func (p *Process) Running() bool {
	wpid, err := syscall.Wait4(p.cmd.Process.Pid, nil, syscall.WNOHANG, nil)
	if err != nil {
		return false
	}
	return wpid == 0
}

// SetInitPid sets the pid of the bwrap init fork.  This should not be called
// except from the sandbox creation routine.
func (p *Process) SetInitPid(pid int) {
	if p.init != nil {
		panic("process: SetInitPid called when already set")
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		panic("process: SetInitPid on invalid process:" + err.Error())
	}
	p.init = proc
}

// NewProcess creates a new Process instance from a Cmd.
func NewProcess(cmd *exec.Cmd) *Process {
	process := new(Process)
	process.cmd = cmd
	return process
}
