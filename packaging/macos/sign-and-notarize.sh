#!/bin/bash
# Sign pyCertWiz.app with a Developer ID, notarize it and staple the ticket.
# Run on your own Mac: the signing certificates never leave it.
#
#   APP_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
#   NOTARY_PROFILE=pycertwiz-notary \
#   packaging/macos/sign-and-notarize.sh dist/pyCertWiz-2.0.2-macos-arm64.dmg
#
# The argument is a .dmg from build-app.sh or the CI artifacts; the signed and
# notarized copy is written next to it as ...-signed.dmg. Store notarization
# credentials once with:
#
#   xcrun notarytool store-credentials pycertwiz-notary \
#       --apple-id you@example.com --team-id TEAMID --password APP_SPECIFIC_PASSWORD
set -euo pipefail

INPUT=${1:?usage: sign-and-notarize.sh PATH/TO/pyCertWiz-<version>-macos-<arch>.dmg}
: "${APP_SIGN_IDENTITY:?set APP_SIGN_IDENTITY to your Developer ID Application identity}"
NOTARY_PROFILE=${NOTARY_PROFILE:-}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'hdiutil detach -quiet "$WORK/mnt" 2>/dev/null || true; rm -rf "$WORK"' EXIT

hdiutil attach -quiet -nobrowse -readonly -mountpoint "$WORK/mnt" "$INPUT"
mkdir -p "$WORK/stage"
cp -R "$WORK/mnt/pyCertWiz.app" "$WORK/stage/"
hdiutil detach -quiet "$WORK/mnt"
APP=$WORK/stage/pyCertWiz.app

# Hardened runtime; sign the nested code first, then the bundle.
find "$APP/Contents" -type f \( -name '*.so' -o -name '*.dylib' -o -perm -u+x \) -print0 |
    xargs -0 codesign --force --options runtime --timestamp --sign "$APP_SIGN_IDENTITY" \
        --entitlements "$ROOT/packaging/macos/entitlements.plist" 2>/dev/null || true
codesign --force --deep --options runtime --timestamp \
    --entitlements "$ROOT/packaging/macos/entitlements.plist" --sign "$APP_SIGN_IDENTITY" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
"$APP/Contents/MacOS/pyCertWiz" --version

ln -s /Applications "$WORK/stage/Applications"
OUTPUT=${INPUT%.dmg}-signed.dmg
VERSION=$("$APP/Contents/MacOS/pyCertWiz" --version | awk '{print $2}')
hdiutil create -quiet -volname "pyCertWiz $VERSION" -srcfolder "$WORK/stage" -ov -format UDZO "$OUTPUT"
codesign --force --timestamp --sign "$APP_SIGN_IDENTITY" "$OUTPUT"

if [ -n "$NOTARY_PROFILE" ]; then
    xcrun notarytool submit "$OUTPUT" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$OUTPUT"
    xcrun stapler validate "$OUTPUT"
    spctl --assess --type open --context context:primary-signature --verbose "$OUTPUT"
else
    echo "Signed but not notarized: set NOTARY_PROFILE to notarize and staple."
fi
echo "signed: $OUTPUT"
