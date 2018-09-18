# sandboxed-tor-browser
Original developer: Yawning Angel (yawning at schwanenlied dot me)

About this repository: I'm not an expert, but I will try to maintain a usable Sandboxed Tor Browser. I think even a bad sandbox is better than no sandbox at all. Any help is welcomed and wanted. Contact: juanjo at avanix dot es

This project aims to be compatible with new Tor Browser 8.0 with Firefox 60 ESR.
This is already working in the latest version 0.0.18.

Tor Browser sandboxed somewhat correctly using bubblewrap.  Obviously only
works on Linux, and will NEVER support anything else since sandboxing is OS
specific.

There are several unresolved issues that affect security and fingerprinting.
Do not assume that this is perfect, merely "an improvement over nothing".

Runtime dependencies:

 * A modern Linux system on x86_64 architecture.
 * bubblewrap >= 0.1.3 (https://github.com/projectatomic/bubblewrap).
 * Gtk+ >= 3.14.0
 * (Optional) PulseAudio
 * (Optional) Adwaita Gtk+-2.0 theme
 * (Optional) libnotify and a Desktop Notification daemon

Build time dependencies:

 * Make
 * A C compiler
 * gb (https://getgb.io/ Yes I know it's behind fucking cloudflare)
 * Go (Tested with 1.7.x)
 * libnotify

Things that the sandbox breaks:

 * Audio (Unless allowed via the config)
 * DRI
 * X11 input methods (IBus requires access to the host D-Bus)
 * Installing addons (Addons are whitelisted)
 * Tor Browser's updater (launcher handles keeping the bundle up to date)

Places where the sandbox could be better:

 * The updater container still mounts `/proc`.
 * PulseAudio is likely unsafe without a protocol filter like X11.
 * X11 is still X11, and despite mitigations is likely still unsafe.

Upstream Bugs:

 * Tor Browser should run without a `/proc` filesystem, worked around in
   the worst possible way.  (https://bugs.torproject.org/20283)
 * OpenGL software rendering is  broken on certain Linux systems.
   (https://bugs.torproject.org/20866)

Notes:

 * Follows the XDG Base Dir specification.
 * Questions that could be answered by reading the code will be ignored.
 * Unless you're capable of debugging it, don't use it, and don't contact me
   about it.
 * By default the sandbox `~/Desktop` and `~/Downloads` directories are mapped
   to the host `~/.local/share/sandboxed-tor-browser/tor-browser/Browser/[Desktop,Downloads]`
   directories.
 * https://git.schwanenlied.me/yawning/sandboxed-tor-browser/wiki has something
   resembling build instructions, that may or may not be up to date.
