// utils.go - Gtk+ utillity routines.
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

package gtk

import (
	"fmt"

	"github.com/gotk3/gotk3/glib"
	gtk3 "github.com/gotk3/gotk3/gtk"
)

type errorInvalidBuilderObject struct {
	obj glib.IObject
}

func (e *errorInvalidBuilderObject) Error() string {
	return fmt.Sprintf("unexpected GtkBuilder object: %v", e.obj)
}

func newInvalidBuilderObject(obj glib.IObject) error {
	return &errorInvalidBuilderObject{obj}
}

// Go is so fucking stupid, since this could easily be a single template.

func getBox(b *gtk3.Builder, id string) (*gtk3.Box, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.Box)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getSwitch(b *gtk3.Builder, id string) (*gtk3.Switch, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.Switch)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getEntry(b *gtk3.Builder, id string) (*gtk3.Entry, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.Entry)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getFChooser(b *gtk3.Builder, id string) (*gtk3.FileChooserButton, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.FileChooserButton)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getComboBoxText(b *gtk3.Builder, id string) (*gtk3.ComboBoxText, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.ComboBoxText)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getImage(b *gtk3.Builder, id string) (*gtk3.Image, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.Image)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getLabel(b *gtk3.Builder, id string) (*gtk3.Label, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.Label)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getButton(b *gtk3.Builder, id string) (*gtk3.Button, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.Button)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getCheckButton(b *gtk3.Builder, id string) (*gtk3.CheckButton, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.CheckButton)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getRadioButton(b *gtk3.Builder, id string) (*gtk3.RadioButton, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.RadioButton)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getFrame(b *gtk3.Builder, id string) (*gtk3.Frame, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.Frame)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}

func getTextView(b *gtk3.Builder, id string) (*gtk3.TextView, error) {
	obj, err := b.GetObject(id)
	if err != nil {
		return nil, err
	}
	v, ok := obj.(*gtk3.TextView)
	if !ok {
		return nil, newInvalidBuilderObject(obj)
	}
	return v, nil
}
