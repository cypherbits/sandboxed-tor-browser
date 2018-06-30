gotk3 [![GoDoc](https://godoc.org/github.com/gotk3/gotk3?status.svg)](https://godoc.org/github.com/gotk3/gotk3)
=====

[![Build Status](https://travis-ci.org/gotk3/gotk3.png?branch=master)](https://travis-ci.org/gotk3/gotk3)

The gotk3 project provides Go bindings for GTK+3 and dependent
projects.  Each component is given its own subdirectory, which is used
as the import path for the package.  Partial binding support for the
following libraries is currently implemented:

  - GTK+3 (3.12 and later)
  - GDK 3 (3.12 and later)
  - GLib 2 (2.36 and later)
  - Cairo (1.10 and later)

Care has been taken for memory management to work seamlessly with Go's
garbage collector without the need to use or understand GObject's
floating references.

## Sample Use

The following example can be found in [Examples](https://github.com/gotk3/gotk3-examples/).

```Go
package main

import (
	"github.com/gotk3/gotk3/gtk"
	"log"
)

func main() {
	// Initialize GTK without parsing any command line arguments.
	gtk.Init(nil)

	// Create a new toplevel window, set its title, and connect it to the
	// "destroy" signal to exit the GTK main loop when it is destroyed.
	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		log.Fatal("Unable to create window:", err)
	}
	win.SetTitle("Simple Example")
	win.Connect("destroy", func() {
		gtk.MainQuit()
	})

	// Create a new label widget to show in the window.
	l, err := gtk.LabelNew("Hello, gotk3!")
	if err != nil {
		log.Fatal("Unable to create label:", err)
	}

	// Add the label to the window.
	win.Add(l)

	// Set the default window size.
	win.SetDefaultSize(800, 600)

	// Recursively show all widgets contained in this window.
	win.ShowAll()

	// Begin executing the GTK main loop.  This blocks until
	// gtk.MainQuit() is run. 
	gtk.Main()
}
```

To build the example:

```
$ go build example.go

```

To build this example with older gtk version you should use gtk_3_10 tag:

```
$ go build -tags gtk_3_10 example.go

```

## Documentation

Each package's internal `go doc` style documentation can be viewed
online without installing this package by using the GoDoc site (links
to [cairo](http://godoc.org/github.com/gotk3/gotk3/cairo),
[glib](http://godoc.org/github.com/gotk3/gotk3/glib),
[gdk](http://godoc.org/github.com/gotk3/gotk3/gdk), and
[gtk](http://godoc.org/github.com/gotk3/gotk3/gtk) documentation).

You can also view the documentation locally once the package is
installed with the `godoc` tool by running `godoc -http=":6060"` and
pointing your browser to
http://localhost:6060/pkg/github.com/gotk3/gotk3

## Installation

gotk3 currently requires GTK 3.6-3.16, GLib 2.36-2.40, and
Cairo 1.10 or 1.12.  A recent Go (1.3 or newer) is also required.

For detailed instructions see the wiki pages: [installation](https://github.com/gotk3/gotk3/wiki#installation)

## TODO
- Add bindings for all of GTK+
- Add tests for each implemented binding

## License

Package gotk3 is licensed under the liberal ISC License.
