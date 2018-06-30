// circuits.go - Tor circuit/stream monitor.
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

package tor

import (
	"container/list"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type circuitMonitor struct {
	sync.Mutex

	p       *ctrlProxy
	circs   []string
	circIds map[int]bool
	conns   *list.List
}

func (m *circuitMonitor) updateCircuitStatus(id int) (bool, error) {
	const (
		lineOk        = "250 OK"
		socksPassword = "SOCKS_PASSWORD=\""
	)

	resp, err := m.p.tor.getinfo("circuit-status")
	if resp == nil && err != nil {
		return false, err
	}

	if len(resp.RawLines) <= 2 {
		// No circuits, or error...
		return false, nil
	}

	tag := m.p.socks.getTag() + "\""

	m.Lock()
	defer m.Unlock()

	m.circIds = make(map[int]bool)
	m.circs = make([]string, 0, len(resp.RawLines)-2)

	// Parse each circuit line...
	foundId := false
	for _, v := range resp.RawLines {
		switch v {
		case ".", lineOk, responseCircuitStatus:
			continue
		default:
		}

		splitCirc := splitQuoted(v)
		if len(splitCirc) < 1 {
			continue
		}
		circId, err := strconv.Atoi(splitCirc[0])
		if err != nil {
			continue
		}

		// If it belongs to us (via the socks password tag)...
		mine := false
		for i, vv := range splitCirc[1:] {
			if strings.HasPrefix(vv, socksPassword) {
				if strings.HasSuffix(vv, tag) {
					// Remove our tag...
					splitCirc[i+1] = strings.TrimSuffix(vv, tag) + "\""
					mine = true
					break
				}
			}
		}
		if mine {
			m.circs = append(m.circs, strings.Join(splitCirc, " "))
			m.circIds[circId] = true
			if circId == id {
				foundId = true
			}
		}
	}
	if len(m.circs) == 0 {
		m.circs = nil
	}

	return foundId, nil
}

func (m *circuitMonitor) getCircuitStatus() []string {
	m.Lock()
	defer m.Unlock()
	return m.circs
}

func (m *circuitMonitor) handleEvents() {
	for {
		ev, ok := <-m.p.tor.ctrlEvents
		if !ok {
			break
		}

		if len(ev.RawLines) > 1 {
			continue
		}
		splitEv := splitQuoted(ev.Reply)
		if splitEv[0] != eventStream {
			continue
		}
		if len(splitEv) < 4 {
			continue
		}

		// All the circuit monitor cares about is SENTCONNECT events.
		if splitEv[2] != "SENTCONNECT" {
			continue
		}
		circId, err := strconv.Atoi(splitEv[3])
		if err != nil {
			continue
		}

		// There's no good way to figure out an individual circuit's
		// `SOCKS_PASSWORD` except via `GETINFO circuit-status`, which is
		// attrocious.
		//
		// nb: Just monitoring CIRC events is insufficient to build
		// an accurate view of things, because the the isolation settings
		// aren't guaranteed to be fixed at `BUILT` time (for good reason),
		// and there's no event when it is (booo).

		if ours, err := m.updateCircuitStatus(circId); err != nil || !ours {
			continue
		}

		b := []byte(ev.RawLines[0] + crLf)
		wrFn := func() {
			m.Lock()
			defer m.Unlock()

			for e := m.conns.Front(); e != nil; e = e.Next() {
				c := e.Value.(*ctrlProxyConn)
				c.appConnWrite(b)
			}
		}
		wrFn()
	}
}

func (m *circuitMonitor) register(c *ctrlProxyConn) {
	if c.monitorEle != nil {
		return
	}

	m.Lock()
	defer m.Unlock()
	c.monitorEle = m.conns.PushFront(c)
}

func (m *circuitMonitor) deregister(c *ctrlProxyConn) {
	if c.monitorEle == nil {
		return
	}

	m.Lock()
	defer m.Unlock()
	m.conns.Remove(c.monitorEle)
	c.monitorEle = nil
}

func initCircuitMonitor(p *ctrlProxy) (*circuitMonitor, error) {
	m := new(circuitMonitor)
	m.p = p
	m.conns = list.New()

	if _, err := m.p.tor.ctrl.Request("SETEVENTS %s", eventStream); err != nil {
		return nil, fmt.Errorf("circuitMon: failed to register for circuit/stream events: %v", err)
	}
	go m.handleEvents()

	return m, nil
}
