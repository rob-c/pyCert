# Packaging and releasing

pyCertWiz ships as:

| Package | Built by | Built on | Runs on |
|---|---|---|---|
| wheel and sdist | `python -m build` | any | Python 3.10+ (`pip install pyCertWiz`) |
| AppImage, `.deb`, `.rpm`, Arch package, tarball, x86_64 | `packaging/linux/` | AlmaLinux 8 (glibc 2.28) | RHEL/AlmaLinux 8, Debian 10, Ubuntu 20.04 and newer |
| the same, aarch64 | `packaging/linux/` | AlmaLinux 10 (glibc 2.39) | Ubuntu 24.04, Debian 13, RHEL/AlmaLinux 10 and newer |
| `pyCertWiz.app` in a `.dmg`, arm64 and x86_64 | `packaging/macos/` | macOS 15 | macOS 12 and newer |
| Nix flake | `flake.nix` | nixpkgs 26.05 | Linux and macOS with Nix |

The Linux and macOS packages are [PyInstaller](https://pyinstaller.org) bundles:
one folder holding Python, Qt, `cryptography` and pyCertWiz. A single executable
serves both uses ([packaging/entry.py](../packaging/entry.py)): with no
arguments, as from a desktop launcher or Finder, it opens the GUI; with
arguments it is the `pycertwiz` command line. The `.deb`, `.rpm` and Arch
packages put the bundle in `/opt/pycertwiz`, link `/usr/bin/pycertwiz` and
`/usr/bin/pycert` to it, and install a desktop entry, AppStream metadata and
an icon (`io.github.rob_c.pyCertWiz`).

Python comes from [uv's standalone builds](https://github.com/astral-sh/python-build-standalone),
so TLS uses a current OpenSSL even on AlmaLinux 8. The command line needs
nothing from the system but glibc. The GUI also needs the desktop libraries
every graphical system has: EGL/OpenGL, xkbcommon, fontconfig, D-Bus and the
xcb utility libraries. The `.deb` and `.rpm` packages *recommend* them (the
`.rpm` by library name, so the same package resolves on Fedora, RHEL and
openSUSE), and the Arch package lists them as optional. Following the AppImage
guidelines, fontconfig, FreeType, HarfBuzz and the C++ runtime are left out of
the bundle and come from the host: an older bundled fontconfig cannot read
newer distributions' font configuration, and an older libstdc++ breaks newer
graphics drivers ([pycertwiz.spec](../packaging/pycertwiz.spec)). The minimum glibc is
read from the bundle's own symbol versions and declared as a dependency, so a
package refuses to install on a system too old to run it instead of failing at
start-up.

`cryptography` is always installed from its wheels, which link OpenSSL
statically. Since 49.0 it publishes no Intel macOS wheels, so the Intel `.dmg`
uses the 48.x series; the Apple silicon `.dmg` and every other package use the
current release.

## Building locally

```console
$ make build                    # wheel and sdist in dist/
$ make package-macos            # dist/pyCertWiz-<version>-macos-<arch>.dmg (on a Mac)
$ make package-linux            # in Docker, for this machine's architecture
$ make package-linux ARCH=x86_64   # on Apple silicon: emulated, slower
$ nix build                     # ./result/bin/pycertwiz
```

`make package-linux` runs [packaging/linux/build.sh](../packaging/linux/build.sh)
in an AlmaLinux container (the bundle, in `build/linux/`), then
[packaging/linux/package.sh](../packaging/linux/package.sh) in an Ubuntu
container, which uses
[appimagetool](https://github.com/AppImage/appimagetool) and
[nfpm](https://nfpm.goreleaser.com) to write the packages to `dist/`.

The icon is [packaging/icons/pycertwiz.svg](../packaging/icons/pycertwiz.svg),
the same shield the application draws. [make_icons.py](../packaging/make_icons.py)
renders it at every size (and a `.icns` on macOS).

## Testing the packages

Every package is tested the way a user would get it, end to end, against the
repository's [sandbox CA](../sandbox_ca/README.md).
[packaging/tests/smoke.sh](../packaging/tests/smoke.sh):

1. runs `--version` and `selftest`;
2. opens the GUI before anything is set up, and checks that the first-run
   setup renders;
3. sets up a configuration pinned to the sandbox CA, then requests a user and
   a host certificate, lists, verifies, exports with a new passphrase,
   renews, and runs `check` and `status --refresh`;
4. opens the main window offscreen, and with `SMOKE_X11=1` on a real X server
   (Xvfb).

[container-test.sh](../packaging/tests/container-test.sh) runs it in a clean
distribution container, with the sandbox CA in a second container:

```console
$ make package-test IMAGE=fedora:latest FORMAT=rpm
$ SMOKE_X11=1 packaging/tests/container-test.sh ubuntu:24.04 deb
$ packaging/tests/container-test.sh almalinux:8 appimage
```

Packages are installed the normal way, recommended packages included, so the
GUI must work straight after installing. The AppImage is first run on a bare
system, command line only, and then again once the desktop libraries are
installed.

## Continuous integration

[.github/workflows/packages.yml](../.github/workflows/packages.yml) runs on
every push to `main` and every pull request:

| Job | What it does |
|---|---|
| Wheel and sdist | builds them, `twine check`, installs the wheel in a clean virtualenv, runs the smoke test |
| Linux x86_64 / aarch64 build | the bundle on AlmaLinux 8 / 10, then the AppImage, `.deb`, `.rpm`, Arch package and tarball |
| *format* on *distribution* | installs each package in a clean container and runs the smoke test: Ubuntu 22.04 and 24.04, Debian 12 and 13, AlmaLinux 8, 9 and 10, Fedora, openSUSE Tumbleweed and Arch (x86_64); Ubuntu 24.04, Debian 13, AlmaLinux 10 and Fedora (aarch64); the GUI also on Xvfb on several |
| macOS arm64 / x86_64 | builds the `.app` and `.dmg`, runs the smoke test from the mounted `.dmg`, opens the window on the runner's display (Cocoa), verifies the signature |
| Nix flake | `nix flake check`, `nix build`, the smoke test |

The packages are kept as workflow artifacts.

## Releasing

1. Set the version in `pyproject.toml` and `src/pycert/__init__.py`, and add
   a `## <version>` section to `CHANGELOG.md`.
2. Commit, then tag and push:

   ```console
   $ git tag v2.0.1 && git push origin v2.0.1
   ```

[release.yml](../.github/workflows/release.yml) checks that the tag matches
the version, runs the whole packages workflow, then:

* creates the GitHub Release with every package, a `SHA256SUMS` file and
  signed build provenance (`gh attestation verify FILE --repo rob-c/pyCertWiz`),
  with the release notes taken from the CHANGELOG section;
* publishes the wheel and sdist to PyPI with
  [trusted publishing](https://docs.pypi.org/trusted-publishers/), so no
  token is stored anywhere.

### One-time setup for PyPI

On pypi.org, under *Your projects → Publishing → Add a new pending publisher*,
add: PyPI project `pyCertWiz`, owner `rob-c`, repository `pyCertWiz`, workflow
`release.yml`, environment `pypi`. In the GitHub repository settings, create
the `pypi` environment (optionally requiring a reviewer, so each upload waits
for approval).

### Signing and notarizing the macOS app

CI signs the app ad hoc, which is enough to test it. macOS asks before opening
an ad hoc-signed app downloaded from the internet (Control-click → Open). To
distribute a signed and notarized app, sign it on your own Mac, so the Developer
ID certificate never leaves it:

```console
$ gh release download v2.0.1 --pattern '*.dmg' --dir dist
$ xcrun notarytool store-credentials pycertwiz-notary \
      --apple-id you@example.com --team-id TEAMID --password APP_SPECIFIC_PASSWORD   # once
$ APP_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" NOTARY_PROFILE=pycertwiz-notary \
      packaging/macos/sign-and-notarize.sh dist/pyCertWiz-2.0.1-macos-arm64.dmg
$ gh release upload v2.0.1 dist/pyCertWiz-2.0.1-macos-arm64-signed.dmg
```

[sign-and-notarize.sh](../packaging/macos/sign-and-notarize.sh) re-signs every
library and the app with the hardened runtime, checks the signature, builds a
signed `.dmg`, submits it for notarization, and staples the ticket.
