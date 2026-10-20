#!/bin/bash
# Compiles a watch app (HarmonyOS/OpenHarmony lite wearable, JS), packs it into a .bin and signs it.
#
#   tools/build-watch-app.sh watch-apps/sample          (debug: plain JS)
#   tools/build-watch-app.sh watch-apps/sample release  (release: bytecode)
#
# Command-line equivalent of DevEco Studio's "legacy lite" build:
#   manifest -> ace-loader (webpack lite) -> restool -> haptobin_tool -> hap-sign-tool (bin)
#
# Environment variables (all optional):
#   HUASIDELOAD_SIGNING_DIR    signing folder (default: signing/ in this repo) with signing.env and profiles/
#   HUASIDELOAD_OUT_DIR        output folder (default: WatchApps/ in this repo); the iPhone app bundles the .bin files in it
#   HUASIDELOAD_PHONE_PACKAGE  bundle ID of the iPhone app (default: HUASIDELOAD_BUNDLE_ID from Config/local.env)
#   HUASIDELOAD_SKIP_SIGN=1    stop before signing (compile check)
#   OHOS_SDK                   OpenHarmony SDK API 9 (default: ~/Library/Huawei/Sdk/openharmony/9)
#   NODE16                     Node.js 16 (default: ~/nodejs/bin/node, else node on PATH)
set -euo pipefail

[ $# -ge 1 ] || { sed -n '2,17p' "$0"; exit 1; }
APP="$(cd "$1" && pwd)"
MODE="${2:-debug}"   # debug: plain JS, release: jerry-snapshot bytecode
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SIGNING="${HUASIDELOAD_SIGNING_DIR:-$REPO/signing}"
OUT_DIR="${HUASIDELOAD_OUT_DIR:-$REPO/WatchApps}"
SDK="${OHOS_SDK:-$HOME/Library/Huawei/Sdk/openharmony/9}"
NODE="${NODE16:-$HOME/nodejs/bin/node}"
[ -x "$NODE" ] || NODE="$(command -v node || true)"

fail() { echo "ERROR: $*" >&2; exit 1; }

# Windows (Git Bash): Python is usually "python" (the "python3" alias may be the Microsoft Store stub),
# and paths handed to native tools through environment variables must be Windows paths
python3 -c '' 2>/dev/null || python3() { python "$@"; }
native_path() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }
[ -f "$APP/entry/src/main/config.json" ] || fail "$APP/entry/src/main/config.json not found (is this a watch app folder?)"
[ -d "$SDK/js/build-tools/ace-loader" ] || fail "OpenHarmony SDK not found: $SDK (README > Requirements)"
[ -n "$NODE" ] || fail "Node.js 16 not found (README > Requirements)"
command -v java >/dev/null || fail "Java not found (README > Requirements)"

if [ -z "${HUASIDELOAD_PHONE_PACKAGE:-}" ] && [ -f "$REPO/Config/local.env" ]; then
  # shellcheck disable=SC1091
  source "$REPO/Config/local.env"
  HUASIDELOAD_PHONE_PACKAGE="${HUASIDELOAD_BUNDLE_ID:-}"
fi
PHONE_PACKAGE="${HUASIDELOAD_PHONE_PACKAGE:-com.example.huasideload}"

BUILD="$APP/build"
MAIN="$BUILD/src/main"
rm -rf "$BUILD"
mkdir -p "$BUILD"/{manifest,loader_out_lite/js/default,cache,lite_bin_source,res,out} "$MAIN"

# Sources are copied under build/; __HUASIDELOAD_PHONE_PACKAGE__ in the JS becomes the iPhone app's bundle ID
cp -R "$APP/entry/src/main/." "$MAIN/"
python3 - "$MAIN/js" "$PHONE_PACKAGE" <<'EOF'
import os, sys
root, package = sys.argv[1], sys.argv[2]
for folder, _, files in os.walk(root):
    for name in files:
        if name.endswith(".js"):
            path = os.path.join(folder, name)
            text = open(path, encoding="utf-8").read()
            if "__HUASIDELOAD_PHONE_PACKAGE__" in text:
                open(path, "w", encoding="utf-8").write(text.replace("__HUASIDELOAD_PHONE_PACKAGE__", package))
EOF

{ read -r BUNDLE; read -r NAME; } < <(python3 - "$MAIN" <<'EOF'
import json, sys
main = sys.argv[1]
bundle = json.load(open(f"{main}/config.json"))["app"]["bundleName"]
name = bundle
try:
    for item in json.load(open(f"{main}/resources/base/element/string.json"))["string"]:
        if item["name"] == "app_name":
            name = item["value"]
except FileNotFoundError:
    pass
print(bundle)
print(name.replace("/", "-"))
EOF
)
# Python on Windows prints CRLF line endings
BUNDLE="${BUNDLE%$'\r'}"; NAME="${NAME%$'\r'}"
echo "== $NAME ($BUNDLE), $MODE"

echo "1/5 manifest.json"
python3 - "$MAIN/config.json" "$BUILD/manifest/manifest.json" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1]))
ability = c["module"]["abilities"][0]
json.dump({
    "appID": c["app"]["bundleName"],
    "versionName": c["app"]["version"]["name"],
    "versionCode": c["app"]["version"]["code"],
    "minPlatformVersion": c["app"]["apiVersion"]["compatible"],
    "appName": ability.get("label") or ability["name"],
    "deviceType": c["module"]["deviceType"],
    "window": True,
    "pages": c["module"]["js"][0]["pages"],
    "type": ability["type"],
}, open(sys.argv[2], "w"), indent=2)
EOF

# png/jpg resources are converted to the lite image format (.bin), keeping the folder layout
(cd "$MAIN/resources" && find . -type f \( -iname '*.png' -o -iname '*.jpg' \) -exec cp --parents {} "$BUILD/lite_bin_source/" \;)

echo "2/5 ace-loader (lite, $MODE)"
(cd "$SDK/js/build-tools/ace-loader" && \
  aceModuleRoot="$(native_path "$MAIN/js/default")" aceModuleBuild="$(native_path "$BUILD/loader_out_lite/js/default")" \
  aceManifestPath="$(native_path "$BUILD/manifest/manifest.json")" cachePath="$(native_path "$BUILD/cache")" \
  img2bin=true iconPath="$(native_path "$BUILD/lite_bin_source")" hapMode=$([ "$MODE" = release ] && echo true || echo false) \
  "$NODE" ./node_modules/webpack/bin/webpack.js --config webpack.lite.config.js \
    --env buildMode="$MODE" --env deviceType=liteWearable) > "$BUILD/compile.log" 2>&1 || true
grep -E 'COMPILE RESULT' "$BUILD/compile.log" || true
# The compiler still writes output on errors (a missing module then crashes on the watch): stop here
if grep -q 'COMPILE RESULT:FAIL' "$BUILD/compile.log" || [ ! -f "$BUILD/loader_out_lite/js/default/app.js" ]; then
  grep -E 'ERROR|Error' -A2 "$BUILD/compile.log" || true
  fail "compile failed ($BUILD/compile.log)"
fi

echo "3/5 restool"
"$SDK/toolchains/restool" -i "$MAIN" -p "$BUNDLE" \
  -o "$BUILD/res" -r "$BUILD/res/ResourceTable.txt" -j "$MAIN/config.json" -f | tail -1

echo "4/5 haptobin"
LITE="$BUILD/lite_source"
mkdir -p "$LITE/assets/entry"
cp "$BUILD/res/config.json" "$LITE/config.json"
cp -R "$BUILD/loader_out_lite/js" "$LITE/assets/js"
find "$LITE/assets/js" -name '*.map' -delete
rm -rf "$LITE/assets/js/default/_releaseMap"
cp -R "$BUILD/res/resources" "$LITE/assets/entry/resources"
cp -R "$BUILD/lite_bin_source/." "$LITE/assets/entry/resources/"
cp "$BUILD/res/resources.index" "$LITE/assets/entry/resources.index"
java -jar "$SDK/js/build-tools/binary-tools/haptobin_tool.jar" \
  --project-path "$LITE" --bin-path "$BUILD/out/unsigned.bin" | tail -1

if [ "${HUASIDELOAD_SKIP_SIGN:-}" = 1 ]; then
  echo "Not signed (HUASIDELOAD_SKIP_SIGN=1): $BUILD/out/unsigned.bin"
  exit 0
fi

echo "5/5 sign"
[ -f "$SIGNING/signing.env" ] || fail "$SIGNING/signing.env not found (see signing/README.md)"
# shellcheck disable=SC1091
source "$SIGNING/signing.env"
PROFILE="$SIGNING/profiles/$BUNDLE.p7b"
[ -f "$PROFILE" ] || fail "No debug profile for this app: $PROFILE (README > Your own watch app)"
if [ -n "${SIGN_PASSWORD_FILE:-}" ]; then
  PASS="$(cat "$SIGNING/$SIGN_PASSWORD_FILE")"
else
  PASS="${SIGN_PASSWORD:?signing.env: SIGN_PASSWORD or SIGN_PASSWORD_FILE is required}"
fi
java -jar "$SDK/toolchains/lib/hap-sign-tool.jar" sign-app -mode localSign \
  -keyAlias "$SIGN_KEY_ALIAS" -keyPwd "$PASS" -keystoreFile "$SIGNING/$SIGN_KEYSTORE" -keystorePwd "$PASS" \
  -appCertFile "$SIGNING/$SIGN_CERT" -profileFile "$PROFILE" \
  -inFile "$BUILD/out/unsigned.bin" -inForm bin -signAlg SHA256withECDSA \
  -outFile "$BUILD/out/signed.bin" | grep -E 'success|error|Error' | tail -1
[ -f "$BUILD/out/signed.bin" ] || fail "signing failed"

mkdir -p "$OUT_DIR"
cp "$BUILD/out/signed.bin" "$OUT_DIR/$NAME.bin"
echo "Done: $OUT_DIR/$NAME.bin"
python3 "$REPO/tools/check-watch-bin.py" "$OUT_DIR/$NAME.bin"
