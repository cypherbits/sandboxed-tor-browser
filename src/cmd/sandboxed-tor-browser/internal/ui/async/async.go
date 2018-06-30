// async.go - Async UI task.
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

// Package async provides an async task struct to allow the UI to run background
// tasks.
package async

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"time"

	"git.schwanenlied.me/yawning/grab.git"
)

// ErrCanceled is the error set when an async operation was canceled.
var ErrCanceled = errors.New("async operation canceled")

// Async is the structure containing the bits needed to communicate from
// a long running async task back to the UI (eg: Installation).
type Async struct {
	// Cancel is used to signal cancelation to the task.
	Cancel chan interface{}

	// Done is used to signal completion to the UI.
	Done chan interface{}

	// ToUI is used to pass data from the task.
	ToUI chan interface{}

	// Err is the final completion status.
	Err error

	// UpdateProgress is the function called to give progress feedback to
	// the UI.
	UpdateProgress func(string)
}

// Grab asynchronously downloads the provided URL using the provided grab
// client, periodically invoking the hzFn on forward progress.
func (async *Async) Grab(client *grab.Client, url string, hzFn func(string)) []byte {
	if req, err := grab.NewRequest(url); err != nil {
		async.Err = err
		return nil
	} else {
		req.Buffer = &bytes.Buffer{}
		var resp *grab.Response

		ch := client.DoAsync(req)
		select {
		case resp = <-ch:
		case <-async.Cancel:
			client.CancelRequest(req)
			async.Err = ErrCanceled
			return nil
		}

		// Wait for the transfer to complete.
		t := time.NewTicker(1000 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-async.Cancel:
				client.CancelRequest(req)
				async.Err = ErrCanceled
				return nil
			case <-t.C:
				if resp.IsComplete() {
					if resp.Error != nil {
						async.Err = resp.Error
						return nil
					}
					return req.Buffer.Bytes()
				} else if hzFn != nil {
					remaining := resp.ETA().Sub(time.Now()).Seconds()
					hzFn(fmt.Sprintf("%vs remaining", int(remaining)))
				}
				runtime.Gosched()
			}
		}
	}
}

// NewAsync creates a new Async structure.
func NewAsync() *Async {
	// XXX; Temporarily work around bug #20804, by oversizing
	// the channels a bit.  Things end up getting stuck on channel
	// writes because it's kludged together, this should ensure that
	// the writes succeed.
	async := new(Async)
	async.Cancel = make(chan interface{}, 2)
	async.Done = make(chan interface{}, 2)
	async.ToUI = make(chan interface{})
	return async
}
