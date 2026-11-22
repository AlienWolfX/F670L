#!/usr/bin/env python3
# ============================================================
# ZTE config.bin decryptor / encryptor (unified)
# ============================================================

import os
import sys
import struct
import zlib
import re
import argparse
from io import BytesIO
from hashlib import sha256

try:
    from Cryptodome.Cipher import AES
except ImportError:
    sys.exit("[!] Missing dependency: pip install pycryptodomex")

CONFIG_DIR = "config"


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def resolve_path(user_input, default_name):
    default_path = os.path.join(CONFIG_DIR, default_name)
    if user_input:
        if not user_input.startswith(CONFIG_DIR + os.sep) and not user_input.startswith(CONFIG_DIR + "/"):
            return os.path.join(CONFIG_DIR, user_input)
        return user_input
    return default_path


def parse_dev_info(path):
    """Parse a dev_info.txt with lines like `SN=...` and `MAC=...`."""
    if not os.path.exists(path):
        sys.exit(f"[ERROR] dev-info file not found: {path}")

    values = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            values[k.strip().upper()] = v.strip()

    return values.get("SN"), values.get("MAC")


def load_sn_mac(args):
    """Resolve SN and MAC from CLI args, dev-info file, or legacy _sn.txt/_mac.txt."""
    serial = args.sn
    mac = args.mac

    if (not serial or not mac) and args.dev_info:
        file_sn, file_mac = parse_dev_info(args.dev_info)
        serial = serial or file_sn
        mac = mac or file_mac

    if not serial or not mac:
        # Legacy fallback: config/_sn.txt + config/_mac.txt
        sn_path = os.path.join(CONFIG_DIR, "_sn.txt")
        mac_path = os.path.join(CONFIG_DIR, "_mac.txt")
        if os.path.exists(sn_path) and os.path.exists(mac_path):
            serial = serial or open(sn_path, encoding="utf-8").read().strip()
            mac = mac or open(mac_path, encoding="utf-8").read().strip()

    if not serial:
        sys.exit("[ERROR] Serial not provided. Use --sn, --dev-info, or config/_sn.txt")
    if not mac:
        sys.exit("[ERROR] MAC not provided. Use --mac, --dev-info, or config/_mac.txt")

    serial = serial.strip().upper()
    mac = mac.strip()

    print(f"[+] Serial ONU/ONT: {serial}")
    print(f"[+] MAC ONT: {mac}")
    return serial, mac


def normalize_mac(mac):
    clean = mac.replace(":", "").replace("-", "").replace(".", "").lower()
    if len(clean) != 12:
        sys.exit("[ERROR] Invalid MAC address")
    return clean


def reverse_mac_bytes(mac_clean):
    pairs = [mac_clean[i:i + 2] for i in range(0, 12, 2)]
    return "".join(pairs[::-1])


def derive_key_iv(serial, mac):
    mac_clean = normalize_mac(mac)
    mac_rev = reverse_mac_bytes(mac_clean)
    serial_short = serial[4:] if serial.startswith("ZTE") else serial

    key_str = serial_short.upper() + mac_rev
    iv_str = "ZTE%FN$GponNJ025"

    key = sha256(key_str.encode()).digest()
    iv = sha256(iv_str.encode()).digest()[:16]

    print("\n=== KEY DERIVATION ===\n")
    print("KEY_STR =", key_str)
    print("IV_STR  =", iv_str)
    print("\nAES KEY =", key.hex())
    print("AES IV  =", iv.hex())
    return key, iv


# ------------------------------------------------------------
# Decrypt
# ------------------------------------------------------------

def do_decrypt(args):
    print()

    default_file = os.path.join(CONFIG_DIR, "config.bin")
    if args.config:
        cfg = resolve_path(args.config, "config.bin")
    elif args.input:
        cfg = resolve_path(args.input, "config.bin")
    elif os.path.exists(default_file):
        cfg = default_file
        print(f"[+] Auto-detected config file: {cfg}")
    else:
        raw = input(f"config.bin not found. Enter path [{default_file}]: ").strip()
        cfg = resolve_path(raw, "config.bin") if raw else default_file

    if not os.path.exists(cfg):
        sys.exit(f"[ERROR] File not found: {cfg}")

    serial, mac = load_sn_mac(args)
    key, iv = derive_key_iv(serial, mac)

    with open(cfg, "rb") as f:
        data = f.read()
    print(f"\n[+] Size: {len(data)} bytes")

    outer_magic = b"\x01\x02\x03\x04\x00\x00\x00\x06"
    off = data.find(outer_magic)
    if off < 0:
        sys.exit("[ERROR] Payload signature not found")
    print(f"[+] Payload @ 0x{off:X}")

    chunk_off = off + 60
    _, enc_size, _ = struct.unpack(">3I", data[chunk_off:chunk_off + 12])
    print(f"[+] Encrypted size: {enc_size}")

    enc_start = chunk_off + 12
    encrypted = data[enc_start:enc_start + enc_size]

    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted)
    print(f"[+] Decrypted size: {len(plain)}")

    stage_path = os.path.join(CONFIG_DIR, "stage_decrypted.bin")
    with open(stage_path, "wb") as f:
        f.write(plain)
    print(f"[OK] Saved: {stage_path}")

    inner_magic, inner_type = struct.unpack(">II", plain[:8])
    print("\n=== INNER HEADER ===")
    print(f"magic = 0x{inner_magic:08X}")
    print(f"type  = {inner_type}")

    pos = 60
    decompressed = BytesIO()
    block = 0

    while True:
        hdr = plain[pos:pos + 12]
        if len(hdr) < 12:
            break

        blk_dec, blk_comp, blk_more = struct.unpack(">3I", hdr)
        if blk_comp == 0:
            break

        print(f"\n[BLOCK {block}] dec={blk_dec} comp={blk_comp}")

        chunk = plain[pos + 12:pos + 12 + blk_comp]
        try:
            decompressed.write(zlib.decompress(chunk))
            print("[OK] zlib")
        except Exception as e:
            print("[ERROR]", e)
            break

        pos += 12 + blk_comp
        block += 1
        if blk_more == 0:
            break

    result = decompressed.getvalue()
    xml_path = os.path.join(CONFIG_DIR, "config_decrypted.xml")
    with open(xml_path, "wb") as f:
        f.write(result)
    print(f"\n[OK] Saved: {xml_path}")

    extract_tables(result)


def extract_tables(result):
    print("\n=== TARGET TABLE EXTRACTION ===")

    xml_text = result.decode("utf-8", errors="replace")
    target_tables = ["MgtServer", "PPPIF", "DevAuthInfo"]

    pppif_out = ""
    devauth_out = ""

    for tbl_name in target_tables:
        print(f"\n[+] Table: {tbl_name}")
        print("-" * 40)

        tbl_match = re.search(
            f'<Tbl\\s+name="{tbl_name}"[^>]*>(.*?)</Tbl>',
            xml_text, re.DOTALL,
        )
        if not tbl_match:
            print("    (table not found)")
            continue

        rows = re.findall(
            '<Row\\s+No="(\\d+)"[^>]*>(.*?)</Row>',
            tbl_match.group(1), re.DOTALL,
        )
        if not rows:
            print("    (no rows)")
            continue

        for row_no, row_content in rows:
            print(f"  -> Row {row_no}:")
            dms = re.findall('<DM\\s+name="([^"]*)"\\s+val="([^"]*)"', row_content)
            row_data = dict(dms)

            if dms:
                for name, val in dms:
                    print(f"     {name} = {val}")
            else:
                print("     (no DM parameters)")

            if tbl_name == "PPPIF":
                pppif_out += f"Username = {row_data.get('Username', '')}\n"
                pppif_out += f"Password = {row_data.get('Password', '')}\n"

            elif tbl_name == "DevAuthInfo" and row_data.get("Enable") == "1":
                devauth_out += f"AppID = {row_data.get('AppID', '')}\n"
                devauth_out += f"User = {row_data.get('User', '')}\n"
                devauth_out += f"Pass = {row_data.get('Pass', '')}\n"
                devauth_out += f"Level = {row_data.get('Level', '')}\n\n"

    print("\n=== SAVING EXTRACTED RESULTS ===")

    if pppif_out:
        path = os.path.join(CONFIG_DIR, "pppif_extracted.txt")
        open(path, "w", encoding="utf-8").write(pppif_out)
        print(f"[OK] Saved: {path}")

    if devauth_out:
        path = os.path.join(CONFIG_DIR, "devauthinfo_extracted.txt")
        open(path, "w", encoding="utf-8").write(devauth_out.rstrip() + "\n")
        print(f"[OK] Saved: {path}")
    else:
        print("[!] No DevAuthInfo rows with Enable = 1")


# ------------------------------------------------------------
# Encrypt
# ------------------------------------------------------------

def do_encrypt(args):
    print()

    default_xml = os.path.join(CONFIG_DIR, "config_decrypted.xml")
    if args.input:
        input_xml = resolve_path(args.input, "config_decrypted.xml")
    elif os.path.exists(default_xml):
        input_xml = default_xml
        print(f"[+] Auto-detected XML: {input_xml}")
    else:
        raw = input("Enter path to decrypted XML: ").strip()
        input_xml = resolve_path(raw, "config_decrypted.xml") if raw else default_xml

    output_bin = (
        resolve_path(args.output, "config_new.bin")
        if args.output
        else os.path.join(CONFIG_DIR, "config_new.bin")
    )
    print(f"[+] Output bin: {output_bin}")

    default_orig = os.path.join(CONFIG_DIR, "config.bin")
    if args.original:
        original_bin = resolve_path(args.original, "config.bin")
    elif args.config:
        original_bin = resolve_path(args.config, "config.bin")
    elif os.path.exists(default_orig):
        original_bin = default_orig
        print(f"[+] Auto-detected original config.bin: {original_bin}")
    else:
        raw = input("Enter path to original config.bin: ").strip()
        original_bin = resolve_path(raw, "config.bin") if raw else default_orig

    serial, mac = load_sn_mac(args)
    mac = mac.lower()

    if not os.path.exists(input_xml):
        sys.exit(f"[ERROR] XML not found: {input_xml}")
    if not os.path.exists(original_bin):
        sys.exit(f"[ERROR] Original config.bin not found: {original_bin}")

    key, iv = derive_key_iv(serial, mac)

    CHUNK_SIZE = 65536
    xml_data = open(input_xml, "rb").read()
    print(f"\n[+] XML read: {len(xml_data)} bytes")

    print("\n=== ZLIB COMPRESSION ===\n")

    compressed_blocks = BytesIO()
    pos = 0
    block = 0
    cumulative = 15 * 4

    while pos < len(xml_data):
        chunk = xml_data[pos:pos + CHUNK_SIZE]
        pos += CHUNK_SIZE

        uncompressed_len = len(chunk)
        compressed_chunk = zlib.compress(chunk, zlib.Z_BEST_COMPRESSION)
        compressed_len = len(compressed_chunk)

        is_last = pos >= len(xml_data)
        more = 0 if is_last else cumulative + compressed_len + 12
        if not is_last:
            cumulative += compressed_len + 12

        compressed_blocks.write(struct.pack(">3I", uncompressed_len, compressed_len, more))
        compressed_blocks.write(compressed_chunk)

        print(f"[BLOCK {block}] {uncompressed_len} -> {compressed_len}")
        block += 1

    compressed_data = compressed_blocks.getvalue()

    crc = 0
    pos2 = 0
    while pos2 < len(compressed_data):
        _, blk_comp2, _ = struct.unpack(">3I", compressed_data[pos2:pos2 + 12])
        crc = zlib.crc32(compressed_data[pos2 + 12:pos2 + 12 + blk_comp2], crc) & 0xFFFFFFFF
        pos2 += 12 + blk_comp2
    print(f"\nCRC = 0x{crc:08X}")

    inner_header = struct.pack(
        ">6I",
        0x01020304, 0, len(xml_data), len(compressed_data) + 15 * 4, CHUNK_SIZE, crc,
    )
    inner_header += struct.pack(">I", zlib.crc32(inner_header) & 0xFFFFFFFF)
    inner_header += struct.pack(">8I", *([0] * 8))

    inner_payload = inner_header + compressed_data
    print(f"\n[+] Inner payload: {len(inner_payload)} bytes")

    pad_len = (16 - len(inner_payload) % 16) % 16
    inner_padded = inner_payload + b"\x00" * pad_len

    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(inner_padded)
    print(f"[+] Encrypted: {len(encrypted)} bytes")

    outer_header = struct.pack(">II", 0x01020304, 6) + b"\x00" * 52
    chunk_header = struct.pack(">3I", len(inner_payload), len(encrypted), 0)
    outer_payload = outer_header + chunk_header + encrypted
    print(f"[+] Outer payload: {len(outer_payload)} bytes")

    sig = b"F670L"
    sig_block = struct.pack(">3I", 0x04030201, 0, len(sig)) + sig

    zte_header = bytearray(open(original_bin, "rb").read()[:128])
    full_payload = sig_block + outer_payload
    full_len = len(full_payload)

    orig_hdr_len = struct.unpack("<I", bytes(zte_header[0x44:0x48]))[0]
    print(f"\nOriginal header length: 0x{orig_hdr_len:X}")

    struct.pack_into("<I", zte_header, 0x44, 128)
    struct.pack_into("<I", zte_header, 0x48, full_len)
    print(f"New payload length: 0x{full_len:X}")

    with open(output_bin, "wb") as f:
        f.write(bytes(zte_header))
        f.write(full_payload)

    print(f"\n[OK] Config.bin written: {output_bin}")
    print(f"FILE SIZE: {len(zte_header) + full_len} bytes")
    print("\nReady to restore!")


# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------

def add_device_args(p, config_help):
    p.add_argument("--config", help=config_help)
    p.add_argument("--sn", help="ONU/ONT serial number (e.g. ZTEGXXXXXXXX)")
    p.add_argument("--mac", help="ONT MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    p.add_argument(
        "--dev-info",
        help="Path to dev_info.txt containing SN=... and MAC=... lines",
    )


def main():
    parser = argparse.ArgumentParser(description="ZTE config.bin decrypt/encrypt tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_dec = sub.add_parser("decrypt", help="Decrypt config.bin -> XML")
    p_dec.add_argument("-i", "--input", help="Path to config.bin (legacy alias for --config)")
    add_device_args(p_dec, "Path to config.bin (default: config/config.bin)")

    p_enc = sub.add_parser("encrypt", help="Encrypt XML -> config.bin")
    p_enc.add_argument("-i", "--input", help="Path to decrypted XML (default: config/config_decrypted.xml)")
    p_enc.add_argument("-o", "--output", help="Output bin path (default: config/config_new.bin)")
    p_enc.add_argument("-r", "--original", help="Original config.bin for header (default: config/config.bin)")
    add_device_args(p_enc, "Original config.bin for header (legacy alias for --original)")

    args = parser.parse_args()

    if args.cmd == "decrypt":
        do_decrypt(args)
    elif args.cmd == "encrypt":
        do_encrypt(args)


if __name__ == "__main__":
    main()