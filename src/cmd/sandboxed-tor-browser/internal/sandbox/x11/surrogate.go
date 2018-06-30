// surrogate.go - X11 surrogate proxy.
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

package x11

// #cgo LDFLAGS: -lxcb
//
// #include <xcb/xcb.h>
// #include <xcb/xproto.h>
// #include <stdlib.h>
// #include <string.h>
//
// static int
// query_extension_opcode(xcb_connection_t *conn, const char *name) {
//     xcb_generic_error_t *error = NULL;
//     xcb_query_extension_cookie_t cookie;
//     xcb_query_extension_reply_t *reply;
//     int ret;
//
//     cookie = xcb_query_extension(conn, strlen(name), name);
//     reply = xcb_query_extension_reply(conn, cookie, &error);
//     if (error)
//         return -1;
//
//     ret = reply->major_opcode;
//     free(reply);
//
//     return ret;
// }
import "C"

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	. "cmd/sandboxed-tor-browser/internal/utils"
)

const (
	supportedProtocolMajor = 11
	supportedProtocolMinor = 0

	opGenericEvent   = 35
	opQueryExtension = 98
	opListExtensions = 99
	opNoOperation    = 127
	opExtensionBase  = 128

	errRequest = 1

	repError = 0
	repReply = 1
)

var (
	extensionWhitelist = []string{
		"BIG-REQUESTS",
		"Composite",
		"DAMAGE",
		"GLX",
		"Generic Event Extension",
		"RANDR",
		"RENDER", // Remove this?
		"SHAPE",
		"SYNC",
		"XFIXES",
		"XINERAMA",
		"XInputExtension",
		"XKEYBOARD",

		// Apparently unused, but not obviously horrific:
		//   DOUBLE-BUFFER
		//   DPMS
		//   MIT-SCREEN-SAVER
		//   Present
		//   SGI-GLX
		//   X-Resource
		//   XC-MISC
		//   XFree86-DGA
		//   XFree86-VidModeExtension
		//   XVideo

		// Unsafe:
		//   DRI2
		//   DRI3
		//   RECORD
		//   SECURITY
		//   XTEST

		// Won't work:
		//   MIT-SHM
	}

	extensionOpFwdMap map[byte]string
	extensionOpRevMap map[string]byte
)

func queryAllowedExtensionOpcodes(display string) error {
	cDisplay := C.CString(display)
	defer C.free(unsafe.Pointer(cDisplay))

	conn := C.xcb_connect(cDisplay, nil)
	if ret := C.xcb_connection_has_error(conn); ret != 0 {
		return fmt.Errorf("failed to query X11 extensions: ", ret)
	}
	defer C.xcb_disconnect(conn)

	extensionOpFwdMap = make(map[byte]string)
	extensionOpRevMap = make(map[string]byte)

	for _, v := range extensionWhitelist {
		name := C.CString(v)
		if op := C.query_extension_opcode(conn, name); op > 0 {
			Debugf("sandbox: X11: Extension '%s' -> %d", v, op)
			extensionOpFwdMap[byte(op)] = v
			extensionOpRevMap[v] = byte(op)
		} else {
			Debugf("sandbox: X11: Extension '%s' -> Not Supported", v)
		}
		C.free(unsafe.Pointer(name))
	}

	return nil
}

type Surrogate struct {
	sNet, sAddr string
	pSock       string
	l           net.Listener
}

func (p *Surrogate) Close() {
	os.Remove(p.pSock)
	p.l.Close()
}

func (p *Surrogate) acceptLoop() {
	defer p.l.Close()
	id := 0
	for {
		conn, err := p.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			return
		}

		Debugf("sandbox: X11: New connection: %d", id)

		go func(connID int) {
			defer conn.Close()

			xConn, err := net.Dial(p.sNet, p.sAddr)
			if err != nil {
				return
			}
			defer xConn.Close()

			c := newSurrogateInstance(conn, xConn, connID)
			c.proxyConns()
		}(id)
		id++
	}
}

type surrogateInstance struct {
	sync.WaitGroup
	sync.Mutex

	connID int

	ffConn    net.Conn
	xConn     net.Conn
	xConnLock sync.Mutex

	byteOrder         binary.ByteOrder
	reqSeq            uint16
	replyRewriteQueue []*replyRewrite

	errChan chan error
}

type replyRewrite struct {
	seq   uint16
	body  []byte
	descr string
}

func newSurrogateInstance(ffConn, xConn net.Conn, connID int) *surrogateInstance {
	c := new(surrogateInstance)
	c.connID = connID
	c.ffConn = ffConn
	c.xConn = xConn
	c.reqSeq = 1
	c.replyRewriteQueue = make([]*replyRewrite, 0)
	c.errChan = make(chan error, 2)

	return c
}

func (c *surrogateInstance) consumeClientConnectionSetup() error {
	// uint8_t  byteOrder (0x42 Big Endian, 0x6C Little Endian)
	// uint8_t  unused
	// uint16_t protocol_major_version
	// uint16_t protocol_minor_version
	// uint16_t n
	// uint16_t d
	// uint16_t unused

	var hdr [12]byte
	if _, err := io.ReadFull(c.ffConn, hdr[:]); err != nil {
		return err
	}

	switch hdr[0] {
	case 0x42:
		c.byteOrder = binary.BigEndian
	case 0x6C:
		c.byteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unable to determine byte order")
	}

	protocolMajor := c.byteOrder.Uint16(hdr[2:])
	protocolMinor := c.byteOrder.Uint16(hdr[4:])

	Debugf("sandbox: X11(%d): Protocol %d.%d", c.connID, protocolMajor, protocolMinor)

	if protocolMajor != supportedProtocolMajor || protocolMinor != supportedProtocolMinor {
		return fmt.Errorf("unsupported X protocol: %v.%v", protocolMajor, protocolMinor)
	}

	n := int(c.byteOrder.Uint16(hdr[6:]))
	nPad := pad(n)
	d := int(c.byteOrder.Uint16(hdr[8:]))
	dPad := pad(d)

	if err := writeFull(c.xConn, hdr[:]); err != nil {
		return err
	}

	// uint8_t authorization_protocol_name[n]
	// uint8_t nPad[pad(n)]
	// uint8_t authorization_protocol_data[d]
	// uint8_t dPad[pad{d)]

	Debugf("sandbox: X11(%d): Auth: %d | %d | %d | %d", c.connID, n, nPad, d, dPad)

	if err := copyFull(c.xConn, c.ffConn, int64(n+nPad+d+dPad)); err != nil {
		return err
	}

	return nil
}

func (c *surrogateInstance) consumeClientRequest() error {
	// uint8_t  opCode
	// uint8_t  unused
	// uint16_t length (Includes the header, 4 byte units)

	var hdr [8]byte
	hdrLen := 4

	if _, err := io.ReadFull(c.ffConn, hdr[:hdrLen]); err != nil {
		return err
	}
	opCode := hdr[0]
	reqLen := int(c.byteOrder.Uint16(hdr[2:]))
	if reqLen == 0 { // BIG-REQUEST extension.
		// Technically this needs to be explicitly enabled, but
		// blindly accepting it isn't actively harmful, so whatever.
		//
		// uint32_t big_request_length
		hdrLen += 4
		if _, err := io.ReadFull(c.ffConn, hdr[4:]); err != nil {
			return err
		}
		reqLen = int(c.byteOrder.Uint32(hdr[4:])) // int is 64 bit.
	}

	// The length is in 4 byte units, and includes the "header".
	// Fix this, since we care about how much additional data
	// there is to consume from the client.
	//
	// TODO: Clamp the max request size to something sensible.
	// Theoretically this should be based off the core protocol
	// max, and or the BIG-REQUEST:BigReqEnable reply.
	reqLen *= 4
	if reqLen < hdrLen {
		return fmt.Errorf("invalid X11 request length: %v", reqLen)
	}
	reqLen -= hdrLen

	// Do the "right" thing based on opCode.
	var reqBody []byte
	rejectReq := false

	switch opCode {
	case opQueryExtension:
		// uint16_t n
		// uint16_t unused
		// uint8_t  name[n]
		// uint8_t  pad[pad(n)]

		reqBody = make([]byte, reqLen)
		if _, err := io.ReadFull(c.ffConn, reqBody); err != nil {
			return err
		}

		n := int(c.byteOrder.Uint16(reqBody[0:]))
		extName := string(reqBody[4 : 4+n])

		Debugf("sandbox: X11(%d): Req(#%05d): QueryExtension: '%s'", c.connID, c.reqSeq, extName)

		_, extAllowed := extensionOpRevMap[extName]
		if !extAllowed {
			Debugf("sandbox: X11(%d): Scheduling QueryExtension for rejection: '%s'", c.connID, extName)
			c.scheduleQueryExtensionReplyRewrite("QueryExtension rejection: " + extName)
		}
	case opListExtensions:
		// Firefox doesn't appear to use this, and it needs to dispatch
		// a series of QueryExtension(s) to actually *USE* any.  So this
		// is here primarily as a debugging aid, so it's somewhat obvious
		// when Firefox inevitably goes full fucking retard and starts
		// crashing when there's a disconnect between the two.

		Debugf("sandbox: X11(%d): Req(#%05d): ListExtensions", c.connID, c.reqSeq)

		// The right thing to do when this is required is to rewrite the
		// response to only show the whitelisted and supported extensions.

	default:
		// Debugf("sandbox: X11(%d): Req(#%05d): %03d %03d: %d bytes", c.connID, c.reqSeq, opCode, hdr[1], reqLen)

		if opCode >= opExtensionBase {
			// Check to see if the extension is allowed.
			_, extAllowed := extensionOpFwdMap[opCode]
			if !extAllowed {
				log.Printf("sandbox: X11: WARNING: Rejecting prohibited request: %d", opCode)

				if err := c.injectRequestError(opCode); err != nil {
					return err
				}
				rejectReq = true
			}
		}
	}

	// Just forward on the request and body.
	if !rejectReq {
		if err := writeFull(c.xConn, hdr[:hdrLen]); err != nil {
			return err
		}
		if reqBody != nil {
			if err := writeFull(c.xConn, reqBody); err != nil {
				return err
			}
		} else {
			if err := copyFull(c.xConn, c.ffConn, int64(reqLen)); err != nil {
				return err
			}
		}
	} else {
		// Send a NoOperation request in the place of the request that
		// is getting serviced internally.
		//
		// WARNING: This is essntially a last resort sort of thing, because
		// doing this can/will assertions in the depths of xcb.  See
		// injectServerReply() for more details.
		if err := c.injectNoOperationRequest(); err != nil {
			return err
		}

		// ... and discard the unread body.
		if reqLen > 0 {
			if err := discardFull(c.ffConn, int64(reqLen)); err != nil {
				return err
			}
		}
	}

	// Increment the sequence number.
	c.reqSeq++

	return nil
}

func (c *surrogateInstance) injectRequestError(opCode byte) error {
	// uint8_t  resp_type (0 = Error)
	// uint8_t  code (1 = Request)
	// uint16_t sequence_number
	// uint8_t  unused[4]
	// uint16_t minor_opcode
	// uint8_t  major_opcode
	// uint8_t  unused[21]

	rep := [32]byte{repError, errRequest}
	c.byteOrder.PutUint16(rep[2:], c.reqSeq)
	rep[10] = opCode

	return c.injectServerReply(rep[:])
}

func (c *surrogateInstance) injectNoOperationRequest() error {
	// uint8_t opcode (127)
	// uint8_t unused
	// uint16_t request_length (1 + len(n-4))
	// uint8_t n[] (Optional)

	req := [4]byte{opNoOperation, 0x00, 0x00, 0x00}
	c.byteOrder.PutUint16(req[2:], 1)

	return writeFull(c.xConn, req[:])
}

func (c *surrogateInstance) scheduleQueryExtensionReplyRewrite(descr string) {
	rep := new(replyRewrite)
	rep.seq = c.reqSeq
	rep.body = make([]byte, 32)
	rep.descr = descr

	// uint8_t  resp_type (1 = Reply)
	// uint8_t  unused
	// uint16_t sequence_number
	// uint32_t reply_length (0)
	// uint8_t  present (Technically a bool)
	// uint8_t  major_opcode
	// uint8_t  first_event
	// uint8_t  first_error
	// uint8_t  unused[20]

	rep.body[0] = repReply
	c.byteOrder.PutUint16(rep.body[2:], c.reqSeq)

	c.Lock()
	defer c.Unlock()
	c.replyRewriteQueue = append(c.replyRewriteQueue, rep)
}

func (c *surrogateInstance) consumeServerConnectionSetup() error {
	// The first 8 bytes of the reply, regardless of the status
	// has this sort of layout.
	//
	// uint8_t  status (0 = Failed, 1 = Success, 2 = Authenticate)
	// uint8_t  unused
	// uint16_t protocol_major_version (unused if Authenticate)
	// uint16_t protocol_minor_version (unused if Authenticate)
	// uint16_t ad_length (In 4 byte units)
	// uint8_t  additional_data[ad_length*4]
	//
	// For our purposes, we only really care about status and ad_length.

	var hdr [8]byte
	if _, err := io.ReadFull(c.xConn, hdr[:]); err != nil {
		return err
	}
	adLen := int(c.byteOrder.Uint16(hdr[6:])) * 4

	if err := writeFull(c.ffConn, hdr[:]); err != nil {
		return err
	}
	if err := copyFull(c.ffConn, c.xConn, int64(adLen)); err != nil {
		return err
	}

	switch hdr[0] {
	case 0:
		return fmt.Errorf("X11 server refused connection")
	case 1:
		return nil
	case 2:
		// I have no idea what exists that requires this, but it's
		// unsupported. Patches accepted.
		return fmt.Errorf("X11 server requires additional authentication")
	default:
		return fmt.Errorf("X11 server returned unknown connection status: %d", hdr[0])
	}
}

func (c *surrogateInstance) consumeServerReply() error {
	// Everything follows this sort of structure.
	//
	// uint8_t  resp_type (0 = Error, 1 = Reply, ... = Event)
	// uint8_t  unused
	// uint16_t sequence_number
	// uint32_t reply_length (In 4 byte units, if Reply or GenericEvent)
	// uint8_t  opaque[24]
	// uint8_t  reply[reply_length * 4]
	//
	// ... So the base size of everything is 32 bytes, followed by
	// reply_length * 4 bytes of additional data. Simple.

	var hdr [32]byte
	if _, err := io.ReadFull(c.xConn, hdr[:]); err != nil {
		return err
	}
	repLen := 0
	if hdr[0] == repReply || hdr[0] == opGenericEvent {
		repLen = int(c.byteOrder.Uint32(hdr[4:])) * 4
	}

	seq := c.byteOrder.Uint16(hdr[2:])
	// Debugf("sandbox: X11(%d): Rep(#%05d): %d: %d bytes", c.connID, seq, hdr[0], 32+repLen)

	// Check to see if the reply needs to be rewritten.
	c.Lock()
	var rewrite *replyRewrite
	if len(c.replyRewriteQueue) > 0 {
		if seq == c.replyRewriteQueue[0].seq {
			switch hdr[0] {
			case repReply:
				rewrite = c.replyRewriteQueue[0]
				c.replyRewriteQueue = c.replyRewriteQueue[1:]
			case repError:
				c.replyRewriteQueue = c.replyRewriteQueue[1:]
			default:
				// Should this ever happen?
				Debugf("sandbox: X11(%d): Rep(#%05d): %d: Event when expecting response or error", c.connID, seq, hdr[0])
			}

			// GC the slice if it's empty, even though it probably won't
			// grow very large.
			if len(c.replyRewriteQueue) == 0 {
				c.replyRewriteQueue = make([]*replyRewrite, 0)
			}
		}
	}
	c.Unlock()

	if rewrite != nil {
		Debugf("sandbox: X11(%d): Rep(#%05d): Rewriting reply: %s", c.connID, seq, rewrite.descr)

		// Discard the reply body.
		if err := discardFull(c.xConn, int64(repLen)); err != nil {
			return err
		}
		return c.forwardServerReply(rewrite.body, 0)
	}
	return c.forwardServerReply(hdr[:], repLen)
}

func (c *surrogateInstance) forwardServerReply(hdr []byte, repLen int) error {
	c.xConnLock.Lock()
	defer c.xConnLock.Unlock()

	if err := writeFull(c.ffConn, hdr); err != nil {
		return err
	}
	if repLen > 0 {
		if err := copyFull(c.ffConn, c.xConn, int64(repLen)); err != nil {
			return err
		}
	}
	return nil
}

func (c *surrogateInstance) injectServerReply(hdr []byte) error {
	// HACK:
	//
	// libX11/tree/src/xcb_io.c:poll_for_event(Display *dpy) will assert
	// if it gets replies out of order, even though it should be able to
	// handle such things.
	//
	// This ugly hack is probably ok for now, since this is only used
	// to reject misbehaving clients that are sending requests to unsupported
	// or proscribed extensions, and the alternative is to crash horribly.

	time.Sleep(100 * time.Millisecond)

	c.xConnLock.Lock()
	defer c.xConnLock.Unlock()

	// This only is used to inject standard replies.
	if len(hdr) != 32 {
		panic("BUG: attempting to inject malformed server reply")
	}

	Debugf("sandbox: X11(%d): Rep(#%05d): Injected", c.connID, c.reqSeq)

	return writeFull(c.ffConn, hdr)
}

func (c *surrogateInstance) proxyConns() {
	// Handle the X11 Connection Setup messages.  This is mostly a no-op,
	// except that it needs to be parsed to determine byte order and so
	// that the request/response+event+error handling can happen.

	if err := c.consumeClientConnectionSetup(); err != nil {
		Debugf("sandbox: X11: Failed to process client connection setup: %v", err)
		return
	}

	if err := c.consumeServerConnectionSetup(); err != nil {
		Debugf("sandbox: X11: Failed to process server connection setup: %v", err)
		return
	}

	// Kick off the main request and response+event+error handlers.

	c.Add(2)
	go func() {
		// X11 -> Client

		defer c.Done()
		defer c.ffConn.Close()
		defer c.xConn.Close()

		for {
			if err := c.consumeServerReply(); err != nil {
				c.errChan <- err
				break
			}
		}
	}()
	go func() {
		// Client -> X11

		defer c.Done()
		defer c.xConn.Close()
		defer c.ffConn.Close()

		for {
			if err := c.consumeClientRequest(); err != nil {
				c.errChan <- err
				break
			}
		}
	}()
	c.Wait()

	// Maybe display errors off errChan, whatever, who cares.
}

func launchSurrogate(xSock, pSock, display string) (*Surrogate, error) {
	p := new(Surrogate)
	p.sNet = "unix"
	p.sAddr = xSock
	p.pSock = pSock

	// (Re)-Initialize the extension whitelist.
	//
	// XXX: Yes, in theory there is a TOCTOU vulnerability here if the
	// X server happens to reassign opcodes to various extensions between
	// connections.  But Xorg doesn't do that, so it's purely theoretical.
	//
	// The alternative would be to incrementally build this list up by
	// sniffing QueryExtension requests and it's replies, but it's a lot
	// of work, and I suspect would be somewhat fragile.
	err := queryAllowedExtensionOpcodes(display)
	if err != nil {
		return nil, err
	}

	os.Remove(p.pSock)
	p.l, err = net.Listen("unix", p.pSock)
	if err != nil {
		return nil, err
	}

	go p.acceptLoop()

	return p, nil
}

func pad(n int) int {
	return (4 - (n & 0x3)) & 0x3
}

func writeFull(c io.Writer, b []byte) error {
	if n, err := c.Write(b); err != nil {
		return err
	} else if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

func copyFull(dst io.Writer, src io.Reader, n int64) error {
	if copied, err := io.CopyN(dst, src, n); err != nil {
		return err
	} else if copied != int64(n) {
		return io.ErrShortWrite
	}
	return nil
}

func discardFull(src io.Reader, n int64) error {
	if err := copyFull(ioutil.Discard, src, n); err != nil {
		return err
	}
	return nil
}
