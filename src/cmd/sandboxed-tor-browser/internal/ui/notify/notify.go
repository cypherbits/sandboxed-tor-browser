// notify.go - Desktop Notification interface.
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

// Package notify interfaces with the Destop Notification daemon, as defined
// by the desktop notifications spec, via the libnotify library.
//
// Note: Instead of linking libnotify, the library is opportunistically loaded
// at runtime via dlopen().  This is not applied to glib/gdk as those are
// pulled in by virtue of the application being a Gtk app.
package notify

// #cgo pkg-config: glib-2.0 gdk-3.0
// #cgo LDFLAGS: -ldl
//
// #include <libnotify/notify.h>
// #include <dlfcn.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <assert.h>
//
// extern void actionCallbackHandler(void *, char *);
//
// static int initialized = 0;
// static int supports_actions = 0;
//
// static gboolean (*init_fn)(const char *) = NULL;
// static void (*uninit_fn)(void) = NULL;
// static GList *(*get_server_caps_fn)(void) = NULL;
//
// static NotifyNotification *(*new_fn)(const char *, const char *, const char *) = NULL;
// static void (*update_fn) (NotifyNotification *, const char *, const char *, const char *) = NULL;
// static gboolean (*show_fn)(NotifyNotification *, GError **) = NULL;
// static void (*set_timeout_fn)(NotifyNotification *, gint timeout) = NULL;
// static void (*set_image_fn)(NotifyNotification *, GdkPixbuf *) = NULL;
// static void (*add_action_fn)(NotifyNotification *, const char *, const char *, NotifyActionCallback, gpointer, GFreeFunc) = NULL;
// static void (*close_fn)(NotifyNotification *, GError **) = NULL;
//
// static void
// notify_action_cb(NotifyNotification *notification, char *action, gpointer user_data) {
//   actionCallbackHandler(user_data, action);
// }
//
// static int
// init_libnotify(const char *app_name) {
//    void *handle = NULL;
//    GList *caps;
//
//    if (initialized != 0) {
//      return initialized;
//    }
//    initialized = -1;
//
//    handle = dlopen("libnotify.so.4", RTLD_LAZY);
//    if (handle == NULL) {
//      fprintf(stderr, "ui: Failed to dlopen() 'libnotify.so.4': %s\n", dlerror());
//      goto out;
//    }
//
//    // Load all the symbols that we need.
//    if ((init_fn = dlsym(handle, "notify_init")) == NULL) {
//      fprintf(stderr, "ui: Failed to find 'notify_init()': %s\n", dlerror());
//      goto out;
//    }
//    if ((uninit_fn = dlsym(handle, "notify_uninit")) == NULL) {
//      fprintf(stderr, "ui: Failed to find 'notify_uninit()': %s\n", dlerror());
//      goto out;
//    }
//    if ((get_server_caps_fn = dlsym(handle, "notify_get_server_caps")) == NULL) {
//      fprintf(stderr, "ui: Failed to find 'notify_get_server_caps()': %s\n", dlerror());
//      goto out;
//    }
//    if ((new_fn = dlsym(handle, "notify_notification_new")) == NULL) {
//      fprintf(stderr, "ui: Failed to find 'notify_notification_new()': %s\n", dlerror());
//      goto out;
//    }
//    if ((update_fn = dlsym(handle, "notify_notification_update")) == NULL) {
//      fprintf(stderr, "ui: Failed to find 'notify_notification_update()': %s\n", dlerror());
//      goto out;
//    }
//    if ((show_fn = dlsym(handle, "notify_notification_show")) == NULL) {
//      fprintf(stderr, "ui: Failed to find 'notify_notification_show()': %s\n", dlerror());
//      goto out;
//    }
//    if ((set_timeout_fn = dlsym(handle, "notify_notification_set_timeout")) == NULL) {
//      fprintf(stderr, "ui: Failed to find 'notify_notification_set_timeout()': %s\n", dlerror());
//      goto out;
//    }
//    if ((set_image_fn = dlsym(handle, "notify_notification_set_image_from_pixbuf")) == NULL) {
//      fprintf(stderr, "ui: Failed to find'notify_notification_set_image_from_pixbuf': %s\n", dlerror());
//      goto out;
//    }
//    if ((add_action_fn = dlsym(handle, "notify_notification_add_action")) ==  NULL) {
//      fprintf(stderr, "ui: Failed to find'notify_notification_add_action': %s\n", dlerror());
//      goto out;
//    }
//    if ((close_fn = dlsym(handle, "notify_notification_close")) == NULL) {
//      fprintf(stderr, "ui: Failed to find'notify_notification_close': %s\n", dlerror());
//      goto out;
//    }
//
//    // Initialize libnotify.
//    if (init_fn(app_name) == TRUE) {
//      initialized = 0;
//    }
//
//    // Figure out if we are talking to the stupid fucking Ubuntu notification
//    // daemon, which doesn't support actions.
//    caps = get_server_caps_fn();
//    if (caps != NULL) {
//      GList *c;
//      for (c = caps; c != NULL; c = c->next) {
//         if (strcmp((char*)c->data, "actions") == 0) {
//           supports_actions = 1;
//         }
//      }
//      g_list_foreach(caps, (GFunc)g_free, NULL);
//      g_list_free(caps);
//    }
//
// out:
//    if (initialized != 0 && handle != NULL) {
//      dlclose(handle);
//   }
//    return initialized;
// }
//
// static void
// uninit_libnotify(void) {
//   if (initialized != 0) {
//     return;
//   }
//   initialized = -1;
//   uninit_fn();
// }
//
// static NotifyNotification *
// n_new(const char *summary, const char *body) {
//   if (initialized != 0) {
//     return NULL;
//   }
//   return new_fn(summary, body, NULL);
// }
//
// static void
// n_update(NotifyNotification *n, const char *summary, const char *body) {
//   assert(n != NULL);
//   update_fn(n, summary, body, NULL);
// }
//
// static void
// n_show(NotifyNotification *n) {
//   assert(n != NULL);
//   show_fn(n, NULL);
// }
//
// static void
// n_set_timeout(NotifyNotification *n, int timeout) {
//   assert(n != NULL);
//   set_timeout_fn(n, timeout);
// }
//
// static void
// n_set_image(NotifyNotification *n, void *pixbuf) {
//   assert(n != NULL);
//   set_image_fn(n, GDK_PIXBUF(pixbuf));
// }
//
// static void
// n_add_action(NotifyNotification *n, const char *action, const char *label, void *user_data) {
//   assert(n != NULL);
//   if (supports_actions) {
//     add_action_fn(n, action, label, NOTIFY_ACTION_CALLBACK(notify_action_cb), user_data, NULL);
//   }
// }
//
// static void
// n_close(NotifyNotification *n) {
//   assert(n != NULL);
//   close_fn(n, NULL);
// }
import "C"

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/gotk3/gotk3/gdk"
)

const (
	// EXPIRES_DEFAULT is the default expiration timeout.
	EXPIRES_DEFAULT = C.NOTIFY_EXPIRES_DEFAULT

	// EXPIRES_NEVER is the infinite expiration timeout.
	EXPIRES_NEVER = C.NOTIFY_EXPIRES_NEVER
)

var callbackChans map[unsafe.Pointer]chan string

// Notification is a `NotifyNotification` instance.
type Notification struct {
	n *C.NotifyNotification
}

// ActionChan returns the channel that actions will be written to.
func (n *Notification) ActionChan() chan string {
	return callbackChans[unsafe.Pointer(n.n)]
}

// Update updates the notification.  Like the libnotify counterpart, Show()
// must be called to refresh the notification.
func (n *Notification) Update(summary, body string, icon *gdk.Pixbuf) {
	cSummary := C.CString(summary)
	defer C.free(unsafe.Pointer(cSummary))
	cBody := C.CString(body)
	defer C.free(unsafe.Pointer(cBody))

	C.n_update(n.n, cSummary, cBody)
	n.SetImage(icon)
}

// Show (re-)displays the notification.
func (n *Notification) Show() {
	C.n_show(n.n)
}

// SetTimeout sets the notification timeout to the value specified in
// milliseconds.
func (n *Notification) SetTimeout(timeout int) {
	C.n_set_timeout(n.n, C.int(timeout))
}

// SetImage sets the notification image to the specified GdkPixbuf.
func (n *Notification) SetImage(pixbuf *gdk.Pixbuf) {
	C.n_set_image(n.n, unsafe.Pointer(pixbuf.GObject))
}

// AddAction adds an action to the notification.
func (n *Notification) AddAction(action, label string) {
	cAction := C.CString(action)
	defer C.free(unsafe.Pointer(cAction))
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	C.n_add_action(n.n, cAction, cLabel, unsafe.Pointer(n))
}

// Close hides the specified nitification.
func (n *Notification) Close() {
	C.n_close(n.n)
}

// ErrNotSupported is the error returned when libnotify is missing or has
// failed to initialize.
var ErrNotSupported = errors.New("libnotify not installed or service not running")

// Init initializes the Desktop Notification interface.
func Init(appName string) error {
	cstr := C.CString(appName)
	defer C.free(unsafe.Pointer(cstr))
	if C.init_libnotify(cstr) != 0 {
		return ErrNotSupported
	}
	return nil
}

// Uninit cleans up the Desktop Notification interface, prior to termination.
func Uninit() {
	C.uninit_libnotify()
}

// New returns a new Notification.
func New(summary, body string, icon *gdk.Pixbuf) *Notification {
	cSummary := C.CString(summary)
	defer C.free(unsafe.Pointer(cSummary))
	cBody := C.CString(body)
	defer C.free(unsafe.Pointer(cBody))

	n := new(Notification)
	n.n = C.n_new(cSummary, cBody)
	if n.n == nil {
		panic("libnotify: notify_notification_new() returned NULL")
	}
	callbackChans[unsafe.Pointer(n.n)] = make(chan string)

	runtime.SetFinalizer(n, func(n *Notification) {
		delete(callbackChans, unsafe.Pointer(n.n))
		C.g_object_unref(C.gpointer(n.n))
	})
	n.SetImage(icon)

	return n
}

//export actionCallbackHandler
func actionCallbackHandler(nPtr unsafe.Pointer, actionPtr *C.char) {
	action := C.GoString(actionPtr)
	n := (*Notification)(nPtr)
	ch := n.ActionChan()
	go func() {
		ch <- action
	}()
}

func init() {
	callbackChans = make(map[unsafe.Pointer]chan string)
}
