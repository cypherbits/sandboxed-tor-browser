// rlimit.go - Resource limits.
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

import "syscall"

func lowerRlimit(resource int, newHard uint64) error {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(resource, &lim); err != nil {
		return err
	}

	needsSet := false
	if newHard < lim.Max {
		lim.Max = newHard
		needsSet = true
	}
	if newHard < lim.Cur {
		lim.Cur = newHard
		needsSet = true
	}
	if !needsSet {
		return nil
	}

	return syscall.Setrlimit(resource, &lim)
}

// SetSensibleRlimits conservatively lowers the rlimits to values that will
// happily support firefox, the updater, tor, and obfs4proxy.
//
// XXX; In the future, this should be applied to each process individually.
// I still need to think about what I'll do for the things that are unset,
// because it should be tied into the UI.
func SetSensibleRlimits() error {
	const (
		limStack = 8 * 1024 * 1024 // 8 MiB Firefox uses a lot with js...
		limRSS   = 0               // No effect as of 2.6.x...
		// limNproc      = 512
		limNofile     = 1024 // Could maybe go as low as 512...
		limMlock      = 0    // This might need to be increased later.
		limLocks      = 32
		limSigpending = 64
		limMsgqueue   = 0 // Disallowed by seccomp.
		limNice       = 0
		limRtprio     = 0
		limRttime     = 0

		// The syscall package doesn't expose these.
		RLIMIT_RSS = 5
		// RLIMIT_NPROC      = 6
		RLIMIT_MLOCK      = 8
		RLIMIT_LOCKS      = 10
		RLIMIT_SIGPENDING = 11
		RLIMIT_MSGQUEUE   = 12
		RLIMIT_NICE       = 13
		RLIMIT_RTPRIO     = 14
		RLIMIT_RTTIME     = 15
	)

	if err := lowerRlimit(syscall.RLIMIT_STACK, limStack); err != nil {
		return err
	}
	if err := lowerRlimit(RLIMIT_RSS, limRSS); err != nil {
		return err
	}
	// if err := lowerRlimit(RLIMIT_NPROC, limNproc); err != nil {
	//	return err
	// }
	if err := lowerRlimit(syscall.RLIMIT_NOFILE, limNofile); err != nil {
		return err
	}
	if err := lowerRlimit(RLIMIT_MLOCK, limMlock); err != nil {
		return err
	}
	if err := lowerRlimit(RLIMIT_LOCKS, limLocks); err != nil {
		return err
	}
	if err := lowerRlimit(RLIMIT_SIGPENDING, limSigpending); err != nil {
		return err
	}
	if err := lowerRlimit(RLIMIT_MSGQUEUE, limMsgqueue); err != nil {
		return err
	}
	if err := lowerRlimit(RLIMIT_NICE, limNice); err != nil {
		return err
	}
	if err := lowerRlimit(RLIMIT_RTPRIO, limRtprio); err != nil {
		return err
	}
	if err := lowerRlimit(RLIMIT_RTTIME, limRttime); err != nil {
		return err
	}

	return nil
}
