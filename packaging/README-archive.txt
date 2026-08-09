Starling
========

A Mumble server. One file: every part of it runs in this one process.

  https://github.com/Fancy-Mumble/starling


Running it
----------

Linux, macOS:     ./starling --all-in-one
Windows:          double-click start-starling.cmd
                  (or: starling.exe --all-in-one)

The first start writes a configuration, creates the administrator account and
prints both, including a SuperUser password that is shown once and stored only
as a hash. Write it down. If you lose it:

  starling set-superuser-password <new password>

Then point a Mumble client at localhost:64738 and log in as SuperUser.


Where it keeps things
---------------------

Linux      ~/.config/starling/starling.toml
           ~/.local/share/starling/
macOS      ~/Library/Application Support/Starling/starling.toml
           ~/Library/Application Support/Starling/
Windows    %APPDATA%\Starling\starling.toml
           %LOCALAPPDATA%\Starling\

The data directory holds the account databases and the TLS certificate that is
this server's identity. Mumble clients recognise a server by that certificate,
so back the directory up: replacing it looks to every client that has connected
like a different server.

The configuration file is yours from the moment it is written. Starling reads
it and never rewrites it. It is a copy of starling.example.toml, next to this
file, with comments on every setting worth changing. A different file:

  starling --all-in-one --config /path/to/other.toml


macOS: the first time
---------------------

These builds are not signed with an Apple developer certificate, so Gatekeeper
will refuse the binary until you say otherwise:

  xattr -dr com.apple.quarantine /path/to/starling

Or open the containing folder in Finder, right-click the binary, and choose
Open.


Letting other people in
-----------------------

Port 64738 has to be reachable, TCP and UDP -- TCP carries the control channel
and text, UDP carries voice. Forward both if the server is behind a router, and
open both in the firewall.

By default the server is not listed anywhere public and has no password; anyone
who knows the address can join. Both are settings in the configuration file.
