#!/usr/bin/env python3
"""Turns an unsigned hvigor build (.app with a lite wearable .hap inside) into a signed watch .bin.

    python3 tools/sign-hvigor-app.py build.app [out.bin]

1. Cleans the packed config.json: hvigor adds fields the watch's installer rejects (app.appEnvironments,
   apiVersion.compileSdkVersion/compileSdkType, deviceConfig.default.debug) and may leave a com.example
   module.package.
2. Packs the .hap entries into the lite .bin layout (0xBE, package, then [name][path][length][content]).
3. Signs it with hap-sign-tool like tools/build-watch-app.sh (signing/signing.env, signing/profiles/<package>.p7b).

Environment: OHOS_SDK (OpenHarmony SDK with toolchains/lib/hap-sign-tool.jar), java on PATH.
"""
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def clean_config(raw):
    config = json.loads(raw.decode("utf-8").lstrip("﻿"))
    app = config.get("app", {})
    app.pop("appEnvironments", None)
    api = app.get("apiVersion")
    if isinstance(api, dict):
        api.pop("compileSdkVersion", None)
        api.pop("compileSdkType", None)
    device = config.get("deviceConfig")
    if isinstance(device, dict) and isinstance(device.get("default"), dict):
        device["default"].pop("debug", None)
        if not device["default"]:
            device.pop("default")
    module = config.get("module", {})
    if str(module.get("package", "")).startswith("com.example"):
        module["package"] = app.get("bundleName")
    return config, json.dumps(config, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def hap_to_bin(hap_bytes):
    with zipfile.ZipFile(io.BytesIO(hap_bytes)) as hap:
        files = {info.filename: hap.read(info) for info in hap.infolist() if not info.is_dir()}
    config, files["config.json"] = clean_config(files["config.json"])
    bundle = config["app"]["bundleName"].encode()
    out = [b"\xbe", struct.pack(">I", len(bundle)), bundle]
    for name in sorted(files, key=lambda n: (n.count("/"), n)):
        directory, _, base = name.rpartition("/")
        path = ("/" + directory).encode() if directory else b""
        out += [struct.pack(">I", len(base.encode())), base.encode(),
                struct.pack(">I", len(path)), path,
                struct.pack(">Q", len(files[name])), files[name]]
    return config, b"".join(out)


def read_env(path):
    env = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key] = value
    return env


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    with zipfile.ZipFile(sys.argv[1]) as app:
        hap_name = next(n for n in app.namelist() if n.endswith(".hap"))
        config, unsigned = hap_to_bin(app.read(hap_name))
    bundle = config["app"]["bundleName"]
    name = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), bundle + ".bin")

    signing = os.environ.get("HUASIDELOAD_SIGNING_DIR", os.path.join(REPO, "signing"))
    env = read_env(os.path.join(signing, "signing.env"))
    password = (open(os.path.join(signing, env["SIGN_PASSWORD_FILE"]), encoding="utf-8").read().strip()
                if env.get("SIGN_PASSWORD_FILE") else env["SIGN_PASSWORD"])
    profile = os.path.join(signing, "profiles", bundle + ".p7b")
    if not os.path.isfile(profile):
        sys.exit(f"No debug profile for {bundle}: {profile}")
    tool = os.path.join(os.environ["OHOS_SDK"], "toolchains", "lib", "hap-sign-tool.jar")

    with tempfile.TemporaryDirectory() as tmp:
        unsigned_path = os.path.join(tmp, "unsigned.bin")
        open(unsigned_path, "wb").write(unsigned)
        result = subprocess.run(
            ["java", "-jar", tool, "sign-app", "-mode", "localSign",
             "-keyAlias", env["SIGN_KEY_ALIAS"], "-keyPwd", password,
             "-keystoreFile", os.path.join(signing, env["SIGN_KEYSTORE"]), "-keystorePwd", password,
             "-appCertFile", os.path.join(signing, env["SIGN_CERT"]), "-profileFile", profile,
             "-inFile", unsigned_path, "-inForm", "bin", "-signAlg", "SHA256withECDSA", "-outFile", name],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        if not os.path.isfile(name):
            sys.exit("signing failed:\n" + result.stdout + result.stderr)
    print(f"{name} ({bundle}, apiVersion {config['app'].get('apiVersion')}, {os.path.getsize(name)} bytes)")


if __name__ == "__main__":
    main()
