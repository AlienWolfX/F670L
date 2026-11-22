# F670L Firmware Research

Tools and notes for unpacking, modifying, rebuilding, and repacking a
F670L-family firmware image. Firmware flashing can permanently damage or
brick the device. Keep a known-good recovery method and an original copy of
the firmware available before proceeding.

## Requirements

- Linux/WSL; the scripts invoke native Linux JFFS2 tools.
- Python 3.
- `binwalk`.
- `jefferson`.
- `mkfs.jffs2` and `sumtool`.
- `dtc` only if extracting device-tree blobs from the kernel partition.

Install the JFFS2 Python extractor with:

```bash
pip install jefferson
```

Paths below assume that commands are run from the repository root.

## 1. Carve the JFFS2 rootfs

Create a raw JFFS2 image from the main firmware:

```bash
python3 firmware_mod/firmware_stuff.py carve f670l.bin \
  -o firmware_mod/rootfs.jffs2
```

The resulting `.json` file records the detected rootfs offset and size.
The script defaults to:

- Rootfs offset: `0x20000`
- Rootfs image size: `23,396,352` bytes

Override both values only if analysis shows that this firmware layout differs:

```bash
python3 firmware_mod/firmware_stuff.py carve f670l.bin \
  --offset 0x20000 \
  --size 23396352 \
  -o firmware_mod/rootfs.jffs2
```

## 2. Extract the rootfs

```bash
sudo jefferson firmware_mod/rootfs.jffs2 -d rootfs
sudo chown -Rh "$(id -u):$(id -g)" rootfs
```

Verify ownership and permissions after extraction. Preserve:

- Root ownership for system directories and binaries.
- Executable permissions on `/bin`, `/sbin`, `/init`, and startup scripts.
- Existing symlinks.
- Empty and runtime directories where required.

Do not copy Windows metadata files into the rootfs. For example, remove:

```bash
find rootfs -name '*:Zone.Identifier' -delete
```

## 3. Remove or edit the CLI restrictions

`rootfs/etc/tdsec/authority.txt` is ZTE's shell policy database. Its bytes are
XOR-inverted (`XOR 0xFF`) and must be transformed before editing.

The file is divided into policy sections, including:

- `[user_permit_list]`: commands permitted by the shell.
- `[ops_permit_list]`: permitted operations.
- `[file_forbid_list]`: blocked files or filename patterns.
- `[forbid_list]`: blocked commands or database operations.
- `[auditfilter_list]`: operations logged or filtered.

The firmware parser has a strict entry limit per section. Keep the original
section structure and do not assume that a wildcard will be accepted.

### Decode

```bash
python3 xor.py \
  rootfs/etc/tdsec/authority.txt \
  -o authority.decoded.txt
```

Keep a backup before making changes:

```bash
cp rootfs/etc/tdsec/authority.txt rootfs/etc/tdsec/authority.txt.bak
```

Edit `authority.decoded.txt` with a plain-text editor.

### Encode

```bash
python3 xor.py \
  authority.decoded.txt \
  -o rootfs/etc/tdsec/authority.txt
```

The same XOR operation is used for decoding and encoding. Verify a known
command appears in both the intended permit section and the relevant forbid
sections. Run a round-trip check when changing the file:

```bash
python3 xor.py \
  rootfs/etc/tdsec/authority.txt \
  -o authority.verify.txt

diff -u authority.decoded.txt authority.verify.txt
```

Note: Limit it to <=99 entries or else it will not work and produce an `ERRNO4.` upon a successful telnet connection.

## 4. Rebuild the JFFS2 rootfs

```bash
sudo chown -Rh root:root rootfs
sudo chmod -R u+rwX,go+rX rootfs

sudo mkfs.jffs2 -l -n -e 0x20000 -m size -r /firmware_mod/root/ -o /firmware_mod/rootfs_mod.jffs2

# Padding
sudo python3 -c '
with open("/home/gab/firmware_mod/rootfs_mod.jffs2", "ab") as f:
    f.write(b"\xff" * (23396352 - f.tell()))
'
```

## 5. Repack the full firmware

```bash
python3 /firmware_mod/firmware_stuff.py repack /firmware_mod/f670l.bin /firmware_mod/rootfs_mod.jffs2 -o ~/firmware_mod/f670l-mod.bin
```

Repacking replaces the JFFS2 region and refreshes firmware header CRC32,
kernel CRC32, and filesystem CRC32 fields.

Verify the original and modified files:

```bash
python3 firmware_mod/firmware_stuff.py verify f670l.bin
python3 firmware_mod/firmware_stuff.py verify f670l-mod.bin
```

Keep `f670l.bin.bak` until the modified firmware has been tested successfully.

To test simply login with your admin account go to the Software Upgrade/Update page and just upload the file.

## Decrypting or encrypting factory configuration

A specialized decryption tool for `version: 5` encrypted config files

```bash
python3 config_decrypt.py decrypt db_default_cfg.xml default.xml
python3 config_decrypt.py encrypt default.xml db_default_cfg.xml
```

This can then be copied back to the device and then compiled back

## Changing the boot partition

Run these commands only from a recovery U-Boot console and only when the
active and backup partitions are understood.

```text
nand read 0x42000000 0x200000 0x20000
mw.b 0x42000016 0x30 1
# 0x30 selects boot partition 0
# 0x31 selects boot partition 1
md.b 0x42000000 0x40

nand erase 0x200000 0x20000
nand write 0x42000000 0x200000 0x20000
reset
```

*Copyright Allen Cruiz*