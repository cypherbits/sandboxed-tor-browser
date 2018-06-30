// surrogate.go - Tor control/socks port surrogates.
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
	"bufio"
	"bytes"
	"container/list"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"cmd/sandboxed-tor-browser/internal/socks5"
	"cmd/sandboxed-tor-browser/internal/ui/config"
)

const (
	crLf = "\r\n"

	cmdProtocolInfo  = "PROTOCOLINFO"
	cmdAuthenticate  = "AUTHENTICATE"
	cmdAuthChallenge = "AUTHCHALLENGE"
	cmdQuit          = "QUIT"
	cmdGetinfo       = "GETINFO"
	cmdGetconf       = "GETCONF"
	cmdSignal        = "SIGNAL"
	cmdSetEvents     = "SETEVENTS"

	eventStream = "STREAM"

	responseOk            = "250 OK" + crLf
	responseCircuitStatus = "250+circuit-status="

	errAuthenticationRequired = "514 Authentication required" + crLf
	errUnrecognizedCommand    = "510 Unrecognized command" + crLf
	errUnspecifiedTor         = "550 Unspecified Tor error" + crLf

	// These responses are entirely synthetic so they don't matter.
	socksAddr = "127.0.0.1:9150"

	aboutAddonsUnsafeHost = "discovery.addons.mozilla.org"
)

func copyLoop(upConn, downConn net.Conn) {
	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	cpFn := func(a, b net.Conn) {
		defer wg.Done()
		defer a.Close()
		defer b.Close()

		_, err := io.Copy(a, b)
		errChan <- err
	}

	go cpFn(upConn, downConn)
	go cpFn(downConn, upConn)

	wg.Wait()
}

type passthroughProxy struct {
	sNet, sAddr string
	l           net.Listener
}

func (p *passthroughProxy) close() {
	p.l.Close()
}

func (p *passthroughProxy) acceptLoop() {
	defer p.l.Close()
	for {
		conn, err := p.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			return
		}

		go func() {
			defer conn.Close()

			downConn, err := net.Dial(p.sNet, p.sAddr)
			if err != nil {
				return
			}
			defer downConn.Close()

			copyLoop(conn, downConn)
		}()
	}
}

func launchPassthroughProxy(hostNet, hostAddr, destNet, destAddr string) (*passthroughProxy, error) {
	p := new(passthroughProxy)
	p.sNet, p.sAddr = destNet, destAddr

	var err error
	p.l, err = net.Listen(hostNet, hostAddr)
	if err != nil {
		return nil, err
	}
	go p.acceptLoop()

	return p, nil
}

type socksProxy struct {
	sync.RWMutex
	sPath       string
	sNet, sAddr string
	tag         string

	l net.Listener
}

func (p *socksProxy) close() {
	p.l.Close()
}

func (p *socksProxy) newTag() error {
	p.Lock()
	defer p.Unlock()

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	p.tag = "sandboxed-tor-browser:" + hex.EncodeToString(b[:])

	return nil
}

func (p *socksProxy) getTag() string {
	p.RLock()
	defer p.RUnlock()
	return ":" + p.tag
}

func (p *socksProxy) acceptLoop() {
	defer p.l.Close()

	for {
		conn, err := p.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			log.Printf("failed to accept SOCKS conn: %v", err)
			return
		}
		go p.handleConn(conn)
	}
}

func (p *socksProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	// Do the SOCKS5 protocol chatter with the application.
	req, err := socks5.Handshake(conn)
	if err != nil {
		return
	}

	// Append our isolation tag.
	if err := p.rewriteTag(conn, req); err != nil {
		req.Reply(socks5.ReplyGeneralFailure)
		return
	}

	// Redispatch the modified SOCKS5 request upstream.
	upConn, err := socks5.Redispatch(p.sNet, p.sAddr, req)
	if err != nil {
		req.Reply(socks5.ErrorToReplyCode(err))
		return
	}
	defer upConn.Close()

	// Complete the SOCKS5 handshake with the app.
	if err := req.Reply(socks5.ReplySucceeded); err != nil {
		return
	}

	copyLoop(upConn, conn)
}

func (p *socksProxy) rewriteTag(conn net.Conn, req *socks5.Request) error {
	if req.Auth.Uname == nil {
		// If the socks request ever isn't using username/password isolation,
		// fail the request, since it's an upstream bug, instead of trying to
		// do a kludgy workaround.
		//
		// See https://bugs.torproject.org/20195
		return fmt.Errorf("invalid isolation requested by Tor Browser")
	}
	req.Auth.Passwd = append(req.Auth.Passwd, []byte(p.getTag())...)
	// With the current format this should never happen, ever.
	if len(req.Auth.Passwd) > 255 {
		return fmt.Errorf("failed to redispatch, socks5 password too long")
	}
	return nil
}

func launchSocksProxy(cfg *config.Config, tor *Tor) (*socksProxy, error) {
	p := new(socksProxy)
	if err := p.newTag(); err != nil {
		return nil, err
	}

	var err error
	p.sNet, p.sAddr, err = tor.SocksPort()
	if err != nil {
		return nil, err
	}

	p.sPath = filepath.Join(cfg.RuntimeDir, "socks")
	os.Remove(p.sPath)
	p.l, err = net.Listen("unix", p.sPath)
	if err != nil {
		return nil, err
	}

	go p.acceptLoop()

	return p, nil
}

type ctrlProxyConn struct {
	sync.Mutex

	p             *ctrlProxy
	appConn       net.Conn
	appConnReader *bufio.Reader
	isPreAuth     bool

	monitorEle *list.Element
}

func (c *ctrlProxyConn) appConnWrite(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()

	return c.appConn.Write(b)
}

func (c *ctrlProxyConn) appConnReadLine() (cmd string, splitCmd []string, rawLine []byte, err error) {
	if rawLine, err = c.appConnReader.ReadBytes('\n'); err != nil {
		return
	}

	trimmedLine := bytes.TrimSpace(rawLine)
	splitCmd = strings.Split(string(trimmedLine), " ")
	cmd = strings.ToUpper(strings.TrimSpace(splitCmd[0]))
	return
}

func (c *ctrlProxyConn) processPreAuth() error {
	sentProtocolInfo := false
	for {
		cmd, splitCmd, _, err := c.appConnReadLine()
		if err != nil {
			return err
		}

		switch strings.ToUpper(cmd) {
		case cmdProtocolInfo:
			if sentProtocolInfo {
				c.sendErrAuthenticationRequired()
				return errors.New("client already sent PROTOCOLINFO already")
			}
			sentProtocolInfo = true
			if err = c.onCmdProtocolInfo(splitCmd); err != nil {
				return err
			}
		case cmdAuthenticate:
			_, err = c.appConnWrite([]byte(responseOk))
			c.isPreAuth = false
			return err
		case cmdAuthChallenge:
			// WTF?  We should never see this since PROTOCOLINFO lies about the
			// supported authentication types.
			c.sendErrUnrecognizedCommand()
			return errors.New("client sent AUTHCHALLENGE, when not supported")
		case cmdQuit:
			return errors.New("client requested connection close")
		default:
			c.sendErrAuthenticationRequired()
			return fmt.Errorf("invalid app command: '%s'", cmd)
		}
	}
	return nil
}

func (c *ctrlProxyConn) proxyAndFilerApp() {
	defer c.appConn.Close()

	for {
		cmd, splitCmd, raw, err := c.appConnReadLine()
		if err != nil {
			break
		}

		switch strings.ToUpper(cmd) {
		case cmdProtocolInfo:
			err = c.onCmdProtocolInfo(splitCmd)
		case cmdGetinfo:
			err = c.onCmdGetinfo(splitCmd, raw)
		case cmdSignal:
			err = c.onCmdSignal(splitCmd, raw)
		case cmdSetEvents:
			err = c.onCmdSetEvents(splitCmd, raw)
		case cmdGetconf:
			err = c.onCmdGetconf(splitCmd, raw)
		default:
			err = c.sendErrUnrecognizedCommand()
		}
		if err != nil {
			break
		}
	}
	if c.p.circuitMonitorEnabled {
		c.p.circuitMonitor.deregister(c)
	}
}

func (c *ctrlProxyConn) sendErrAuthenticationRequired() error {
	_, err := c.appConnWrite([]byte(errAuthenticationRequired))
	return err
}

func (c *ctrlProxyConn) sendErrUnrecognizedCommand() error {
	_, err := c.appConnWrite([]byte(errUnrecognizedCommand))
	return err
}

func (c *ctrlProxyConn) sendErrUnspecifiedTor() error {
	_, err := c.appConnWrite([]byte(errUnspecifiedTor))
	return err
}

func (c *ctrlProxyConn) sendErrUnexpectedArgCount(cmd string, expected, actual int) error {
	var err error
	var respStr string
	if expected > actual {
		respStr = "512 Too many arguments to " + cmd + crLf
	} else {
		respStr = "512 Missing argument to " + cmd + crLf
	}
	_, err = c.appConnWrite([]byte(respStr))
	return err
}

func (c *ctrlProxyConn) onCmdProtocolInfo(splitCmd []string) error {
	for i := 1; i < len(splitCmd); i++ {
		v := splitCmd[i]
		if _, err := strconv.ParseInt(v, 10, 32); err != nil {
			respStr := "513 No such version \"" + v + crLf
			_, err := c.appConnWrite([]byte(respStr))
			return err
		}
	}
	respStr := "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL,HASHEDPASSWORD\r\n250-VERSION Tor=\"" + c.p.torVersion + "\"\r\n" + responseOk
	_, err := c.appConnWrite([]byte(respStr))
	return err
}

func (c *ctrlProxyConn) onCmdGetinfo(splitCmd []string, raw []byte) error {
	const (
		argGetinfoSocks          = "net/listeners/socks"
		argGetinfoCircuitStatus  = "circuit-status"
		prefixGetinfoNsId        = "ns/id/"
		prefixGetinfoIpToCountry = "ip-to-country/"
	)
	if len(splitCmd) != 2 {
		return c.sendErrUnexpectedArgCount(cmdGetinfo, 2, len(splitCmd))
	}

	if c.p.circuitMonitorEnabled && (strings.HasPrefix(splitCmd[1], prefixGetinfoNsId) || strings.HasPrefix(splitCmd[1], prefixGetinfoIpToCountry)) {
		// This *could* filter the relevant results to those that are actually
		// part of circuits that the user has, but that seems overly paranoid,
		// and ironically leaks more information.
		if resp, _ := c.p.tor.getinfo(splitCmd[1]); resp != nil {
			respStr := strings.Join(resp.RawLines, crLf) + crLf
			_, err := c.appConnWrite([]byte(respStr))
			return err
		}
		return c.sendErrUnspecifiedTor()
	}

	// Handle the synthetic responses.
	respStr := "552 Unrecognized key \"" + splitCmd[1] + "\"" + crLf
	switch splitCmd[1] {
	case argGetinfoSocks:
		respStr = "250-" + argGetinfoSocks + "=\"" + socksAddr + "\"" + crLf + responseOk
	case argGetinfoCircuitStatus:
		if !c.p.circuitMonitorEnabled {
			break
		}
		respVec := []string{responseCircuitStatus}
		respVec = append(respVec, c.p.circuitMonitor.getCircuitStatus()...)
		respVec = append(respVec, ".", responseOk)
		respStr = strings.Join(respVec, crLf)
	}
	_, err := c.appConnWrite([]byte(respStr))
	return err
}

func (c *ctrlProxyConn) onCmdGetconf(splitCmd []string, raw []byte) error {
	const argBridge = "BRIDGE"
	if len(splitCmd) != 2 {
		return c.sendErrUnexpectedArgCount(cmdGetconf, 2, len(splitCmd))
	}

	if strings.ToUpper(splitCmd[1]) == argBridge && c.p.circuitMonitorEnabled {
		if resp, _ := c.p.tor.getconf(splitCmd[1]); resp != nil {
			respStr := strings.Join(resp.RawLines, crLf) + crLf
			_, err := c.appConnWrite([]byte(respStr))
			return err
		}
		return c.sendErrUnspecifiedTor()
	}

	respStr := "552 Unrecognized configuration key \"" + splitCmd[1] + "\"" + crLf
	_, err := c.appConnWrite([]byte(respStr))
	return err
}

func (c *ctrlProxyConn) onCmdSignal(splitCmd []string, raw []byte) error {
	const argSignalNewnym = "NEWNYM"
	if len(splitCmd) != 2 {
		return c.sendErrUnexpectedArgCount(cmdSignal, 2, len(splitCmd))
	} else if strings.ToUpper(splitCmd[1]) != argSignalNewnym {
		respStr := "552 Unrecognized signal code \"" + splitCmd[1] + "\"" + crLf
		_, err := c.appConnWrite([]byte(respStr))
		return err
	} else {
		if err := c.p.socks.newTag(); err != nil {
			return c.sendErrUnspecifiedTor()
		}
		if err := c.p.tor.newnym(); err != nil {
			return c.sendErrUnspecifiedTor()
		}
		_, err := c.appConnWrite([]byte(responseOk))
		return err
	}
}

func (c *ctrlProxyConn) onCmdSetEvents(splitCmd []string, raw []byte) error {
	if !c.p.circuitMonitorEnabled {
		return c.sendErrUnrecognizedCommand()
	}

	if len(splitCmd) == 1 {
		c.p.circuitMonitor.deregister(c)
		_, err := c.appConnWrite([]byte(responseOk))
		return err
	} else if len(splitCmd) != 2 {
		// Tor Browser only uses "SETEVENTS STREAM" AFAIK.
		return c.sendErrUnexpectedArgCount(cmdSignal, 2, len(splitCmd))
	} else if strings.ToUpper(splitCmd[1]) != eventStream {
		respStr := "552 Unrecognized event \"" + splitCmd[1] + "\"" + crLf
		_, err := c.appConnWrite([]byte(respStr))
		return err
	}
	c.p.circuitMonitor.register(c)
	_, err := c.appConnWrite([]byte(responseOk))
	return err
}

func (c *ctrlProxyConn) handle() {
	defer c.appConn.Close()

	var err error
	if err = c.processPreAuth(); err != nil {
		log.Printf("control port pre-auth error: %v", err)
		return
	}

	c.proxyAndFilerApp()
}

type ctrlProxy struct {
	cPath      string
	socks      *socksProxy
	tor        *Tor
	torVersion string

	circuitMonitorEnabled bool
	circuitMonitor        *circuitMonitor

	l net.Listener
}

func (p *ctrlProxy) close() {
	p.l.Close()
}

func (p *ctrlProxy) acceptLoop() {
	defer p.l.Close()

	for {
		conn, err := p.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			log.Printf("failed to accept control conn: %v", err)
			return
		}
		p.handleConn(conn)
	}
}

func (p *ctrlProxy) handleConn(conn net.Conn) {
	c := &ctrlProxyConn{
		p:             p,
		appConn:       conn,
		appConnReader: bufio.NewReader(conn),
	}
	go c.handle()
}

func launchCtrlProxy(cfg *config.Config, tor *Tor) (*ctrlProxy, error) {
	p := new(ctrlProxy)
	p.socks = tor.socksSurrogate
	p.tor = tor

	// Save the real tor version.  Tor Browser doesn't use PROTOCOLINFO,
	// but we should do the right thing when it does, and this query is
	// serviced entirely from bulb's internal cache.
	if pi, err := p.tor.ctrl.ProtocolInfo(); err != nil {
		return nil, err
	} else {
		p.torVersion = pi.TorVersion
	}

	var err error
	p.cPath = filepath.Join(cfg.RuntimeDir, "control")
	os.Remove(p.cPath)
	p.l, err = net.Listen("unix", p.cPath)
	if err != nil {
		return nil, err
	}

	if cfg.Sandbox.EnableCircuitDisplay {
		p.circuitMonitor, err = initCircuitMonitor(p)
		if err != nil {
			log.Printf("tor: failed to launch circuit display helper: %v", err)
		}
	}
	p.circuitMonitorEnabled = p.circuitMonitor != nil && err == nil

	go p.acceptLoop()

	return p, nil
}
