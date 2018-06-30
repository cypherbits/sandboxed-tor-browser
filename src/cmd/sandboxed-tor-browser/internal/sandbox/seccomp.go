// secomp.go - Sandbox seccomp rules.
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
	"encoding/binary"
	"fmt"
	"os"
	"runtime"

	"github.com/twtiger/gosecco"
	"github.com/twtiger/gosecco/parser"

	"cmd/sandboxed-tor-browser/internal/data"
)

func installTorSeccompProfile(fd *os.File, useBridges bool) error {
	commonAssetFile := "tor-common-" + runtime.GOARCH + ".seccomp"

	assets := []string{commonAssetFile}
	if useBridges {
		assets = append(assets, "tor-obfs4-"+runtime.GOARCH+".seccomp")
	} else {
		assets = append(assets, "tor-"+runtime.GOARCH+".seccomp")
	}

	return installSeccomp(fd, assets)
}

func installTorBrowserSeccompProfile(fd *os.File) error {
	assetFile := "torbrowser-" + runtime.GOARCH + ".seccomp"

	return installSeccomp(fd, []string{assetFile})
}

func installSeccomp(fd *os.File, ruleAssets []string) error {
	defer fd.Close()

	settings := gosecco.SeccompSettings{
		DefaultPositiveAction: "allow",
		DefaultNegativeAction: "ENOSYS",
		DefaultPolicyAction:   "ENOSYS",
		ActionOnX32:           "kill",
		ActionOnAuditFailure:  "kill",
	}

	if len(ruleAssets) == 0 {
		return fmt.Errorf("installSeccomp() called with no rules")
	}

	// Combine the rules into a single source.
	var sources []parser.Source
	for _, asset := range ruleAssets {
		rules, err := data.Asset(asset)
		if err != nil {
			return err
		}
		source := &parser.StringSource{
			Name:    asset,
			Content: string(rules),
		}
		sources = append(sources, source)
	}

	// Compile the combined source into bpf bytecode.
	combined := parser.CombineSources(sources...)
	bpf, err := gosecco.PrepareSource(combined, settings)
	if err != nil {
		return err
	}

	// Install the bpf bytecode.
	if size, limit := len(bpf), 0xffff; size > limit {
		return fmt.Errorf("filter program too big: %d bpf instructions (limit = %d)", size, limit)
	}
	for _, rule := range bpf {
		if err := binary.Write(fd, binary.LittleEndian, rule); err != nil {
			return err
		}
	}

	return nil
}
