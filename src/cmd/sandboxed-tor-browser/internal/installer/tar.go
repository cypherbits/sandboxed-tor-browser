// tar.go - Tar archive extractor.
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

package installer

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ulikunitz/xz"
)

// ErrExtractionCanceled is the error returned when the untar operation was
// canceled.
var ErrExtractionCanceled = errors.New("tar extraction canceled")

// ExtractBundle extracts the supplied tar.xz archive into destDir.  Any writes
// to cancelCh will abort the extraction.
func ExtractBundle(destDir string, bundleTarXz []byte, cancelCh chan interface{}) error {
	// Obliterate the old installation directory.
	os.RemoveAll(destDir)

	if xzr, err := xz.NewReader(bytes.NewReader(bundleTarXz)); err != nil {
		return err
	} else if err = untar(xzr, destDir, cancelCh); err != nil {
		return err
	}
	return nil
}

func untar(r io.Reader, destDir string, cancelCh chan interface{}) error {
	if err := os.MkdirAll(destDir, os.ModeDir|0700); err != nil {
		return err
	}

	stripContainerDir := func(name string) string {
		// Go doesn't have a "split a path into all of it's components"
		// routine, because it's fucking retarded.
		split := strings.Split(name, "/")
		if len(split) > 1 {
			return filepath.Join(split[1:]...)
		}
		return ""
	}

	extractFile := func(dest string, hdr *tar.Header, r io.Reader) error {
		if hdr.Typeflag == tar.TypeSymlink {
			return fmt.Errorf("symlinks not supported: %v", dest)
		}

		f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, hdr.FileInfo().Mode())
		if err != nil {
			return err
		}
		defer os.Chtimes(dest, hdr.AccessTime, hdr.ModTime)
		defer f.Close()
		_, err = io.Copy(f, r)
		return err
	}

	tarRd := tar.NewReader(r)
	for {
		hdr, err := tarRd.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		// Check to see if the user canceled.
		select {
		case <-cancelCh:
			return ErrExtractionCanceled
		default:
			runtime.Gosched()
		}

		name := stripContainerDir(hdr.Name)
		if name == "" {
			// Ensure that this is the container dir being skipped.
			if hdr.FileInfo().IsDir() {
				continue
			}
			return fmt.Errorf("expecting container dir, got file: %v", hdr.Name)
		}
		destName := filepath.Join(destDir, name)

		if hdr.FileInfo().IsDir() {
			if err := os.MkdirAll(destName, hdr.FileInfo().Mode()); err != nil {
				return err
			}
			continue
		}

		if err := extractFile(destName, hdr, tarRd); err != nil {
			return err
		}
	}
	return nil
}
