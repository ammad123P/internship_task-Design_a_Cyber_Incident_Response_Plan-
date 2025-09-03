#Safe ransomware *simulation* (detailed, reversible).

import argparse
import os
import shutil
import hashlib
import json
import base64
from datetime import datetime
from pathlib import Path
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------
# CONFIG (change for your lab)
# -------------------------
TARGET_DIR = Path("C:/lab_test_data/target")    # ORIGINALS (read-only in practice)
STAGING_DIR = Path("C:/lab_test_data/staging")  # COPIES that will be encrypted
RESTORE_DIR = Path("C:/lab_test_data/restored") # Where decrypted files go
MANIFEST = STAGING_DIR / "manifest.json"
RANSOM_NOTE = STAGING_DIR / "RANSOM_NOTE.txt"

# PBKDF2 params
KDF_ITERATIONS = 200_000  # reasonable for lab (increase for real ops)
KEY_LEN = 32  # AES-256

# Safety helper: require this substring to be present in any configured path.
SAFETY_SUBSTRING = "lab_test_data"

# -------------------------
# Utilities
# -------------------------
def assert_safe_paths(*paths: Path):
    for p in paths:
        p_str = str(p.resolve())
        if SAFETY_SUBSTRING not in p_str:
            raise SystemExit(f"REFUSING to operate: path must contain '{SAFETY_SUBSTRING}': {p_str}")

def sha256_of_file(path: Path, block_size=65536):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            h.update(chunk)
    return h.hexdigest()

def derive_key_from_passphrase(passphrase: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase)

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

# -------------------------
# Simulation (encrypt staged copies)
# -------------------------
def simulate(passphrase: bytes):
    # Safety checks
    assert_safe_paths(TARGET_DIR, STAGING_DIR, RESTORE_DIR)

    if not TARGET_DIR.exists():
        raise SystemExit(f"Target directory not found: {TARGET_DIR}")

    # Create staging
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    RESTORE_DIR.mkdir(parents=True, exist_ok=True)

    # Generate a per-run salt and record it (manifest will contain it)
    salt = os.urandom(16)

    manifest = {
        "simulation_time_utc": datetime.utcnow().isoformat() + "Z",
        "source": str(TARGET_DIR),
        "staging": str(STAGING_DIR),
        "restore_target": str(RESTORE_DIR),
        "kdf": {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": KDF_ITERATIONS,
            "salt_b64": b64(salt),
            "key_len": KEY_LEN
        },
        "staged_files": []
    }

    # Walk target and copy files (originals untouched)
    for root, dirs, files in os.walk(TARGET_DIR):
        rel_root = os.path.relpath(root, TARGET_DIR)
        for fname in files:
            src = Path(root) / fname
            dst_dir = STAGING_DIR / rel_root
            dst_dir.mkdir(parents=True, exist_ok=True)
            dst = dst_dir / fname

            # Copy original file to staging (preserve metadata)
            shutil.copy2(src, dst)

            # Compute plaintext SHA256 and size
            plaintext_hash = sha256_of_file(dst)
            size_bytes = dst.stat().st_size

            # Encrypt the staged copy in-place using AES-GCM with passphrase-derived key
            nonce = os.urandom(12)  # AESGCM nonce size recommended 12 bytes
            key = derive_key_from_passphrase(passphrase, salt)
            aesgcm = AESGCM(key)

            with dst.open("rb") as f:
                plaintext = f.read()
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Overwrite the staged copy with ciphertext (originals are still in TARGET_DIR)
            with dst.open("wb") as f:
                f.write(ciphertext)

            manifest["staged_files"].append({
                "relative_path": os.path.normpath(os.path.join(rel_root, fname)),
                "staged_path": str(dst),
                "size_bytes_plaintext": size_bytes,
                "sha256_plaintext": plaintext_hash,
                "nonce_b64": b64(nonce),
                # we do NOT store the raw key. Salt is in manifest; passphrase required to derive key.
            })

            print(f"[sim] staged & encrypted: {dst} (orig size {size_bytes} bytes)")

    # Write manifest
    with MANIFEST.open("w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2)

    # Write ransom note (mock)
    with RANSOM_NOTE.open("w", encoding="utf-8") as rn:
        rn.write("=== MOCK RANSOM NOTE ===\n")
        rn.write("This is a SAFE ransomware simulation.\n")
        rn.write("Files in the staging folder were encrypted as part of an exercise only.\n")
        rn.write("To decrypt, provide the same passphrase used for the simulation and run the 'decrypt' command.\n")
        rn.write(f"Simulation time (UTC): {manifest['simulation_time_utc']}\n")
        rn.write("DO NOT run this script on production data. Use isolated lab only.\n")

    print("\nSimulation COMPLETE.")
    print(f"Manifest: {MANIFEST}")
    print(f"Ransom note: {RANSOM_NOTE}")
    print("IMPORTANT: keep your passphrase safe to allow decryption in this simulation.")

# -------------------------
# Decrypt staged copies into RESTORE_DIR
# -------------------------
def decrypt(passphrase: bytes):
    assert_safe_paths(STAGING_DIR, RESTORE_DIR)
    if not MANIFEST.exists():
        raise SystemExit(f"Manifest not found: {MANIFEST}")

    with MANIFEST.open("r", encoding="utf-8") as mf:
        manifest = json.load(mf)

    salt_b64 = manifest.get("kdf", {}).get("salt_b64")
    if not salt_b64:
        raise SystemExit("Manifest missing salt; cannot derive key.")
    salt = ub64(salt_b64)

    # Attempt to decrypt each file
    failed = []
    success = []
    for entry in manifest["staged_files"]:
        staged_path = Path(entry["staged_path"])
        rel_path = entry["relative_path"]
        nonce = ub64(entry["nonce_b64"])
        if not staged_path.exists():
            failed.append((rel_path, "staged file missing"))
            continue
        with staged_path.open("rb") as f:
            ciphertext = f.read()

        try:
            key = derive_key_from_passphrase(passphrase, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            failed.append((rel_path, f"decryption failed: {e}"))
            continue

        out_path = RESTORE_DIR / rel_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("wb") as out:
            out.write(plaintext)
        # Optionally preserve timestamps or set metadata
        success.append(rel_path)
        print(f"[decrypt] restored: {out_path}")

    print(f"\nDecryption finished. Restored: {len(success)} files. Failed: {len(failed)}")
    if failed:
        print("Failed items:")
        for r, reason in failed:
            print(f" - {r}: {reason}")

# -------------------------
# Status / manifest summary
# -------------------------
def status():
    if not MANIFEST.exists():
        print("No manifest found. Run 'simulate' first.")
        return
    with MANIFEST.open("r", encoding="utf-8") as mf:
        manifest = json.load(mf)
    print(json.dumps({
        "simulation_time_utc": manifest["simulation_time_utc"],
        "source": manifest["source"],
        "staged_files_count": len(manifest["staged_files"]),
    }, indent=2))

# -------------------------
# CLI & Safety confirmation
# -------------------------
def interactive_confirm():
    print("!!! SAFETY WARNING !!!")
    print("This script is for ISOLATED LAB use only. It will NOT modify originals,")
    print("but it WILL encrypt copies in the STAGING folder and store a manifest.")
    print("Make sure you are operating on test data inside a folder containing 'lab_test_data'.")
    resp = input("Type 'I UNDERSTAND' to proceed: ").strip()
    if resp != "I UNDERSTAND":
        raise SystemExit("Aborted by user (safety confirmation not provided).")

def main():
    parser = argparse.ArgumentParser(description="Safe ransomware simulation (lab only).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sim = sub.add_parser("simulate", help="Copy and encrypt staged copies (safe).")
    p_sim.add_argument("--passphrase", "-p", help="Passphrase (not recommended on CLI).")

    p_dec = sub.add_parser("decrypt", help="Decrypt staged copies into restore dir.")
    p_dec.add_argument("--passphrase", "-p", help="Passphrase (not recommended on CLI).")

    p_status = sub.add_parser("status", help="Show manifest summary.")

    args = parser.parse_args()

    # Safety check: ensure configured paths include safety substring
    assert_safe_paths(TARGET_DIR, STAGING_DIR, RESTORE_DIR)

    if args.cmd == "simulate":
        interactive_confirm()
        if args.passphrase:
            passphrase = args.passphrase.encode('utf-8')
        else:
            passphrase = getpass("Enter passphrase to derive encryption key (will not echo): ").encode('utf-8')
        simulate(passphrase)
    elif args.cmd == "decrypt":
        if args.passphrase:
            passphrase = args.passphrase.encode('utf-8')
        else:
            passphrase = getpass("Enter passphrase to derive decryption key (will not echo): ").encode('utf-8')
        decrypt(passphrase)
    elif args.cmd == "status":
        status()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
