"""
SpellForce 1 & 2 - Complete Modding & Localization Suite
Supports CFF Containers (SF1 & SF2), DAT Database Chunks, Binary Scanning/Editing, and Batch PAK Archives.
Includes support for SpellForce 1: Platinum Edition hybrid CFF headers and 62MB Text String Tables.
Features both Balanced BST Generation from Scratch and Meta-Template Injection for SF1 .PAK archives.
"""

import json
import os
import queue
import re
import shutil
import struct
import sys
import threading
import zlib

# ==============================================================================
# ORIGINAL SPELLFORCE 1 CRC32 CHECKSUM ENGINE (IEEE 802.3 Polynomial: 0xEDB88320)
# ==============================================================================

# Pre-generate standard CRC32 table
CRC32_TABLE = []
for i in range(256):
    crc = i
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc >>= 1
    CRC32_TABLE.append(crc)


def calculate_sf1_crc(data, prev_crc=0xFFFFFFFF):
    """Calculates custom CRC32 checksum without final bitwise inversion."""
    crc = prev_crc
    for b in data:
        crc = (crc >> 8) ^ CRC32_TABLE[(crc ^ b) & 0xFF]
    return crc


# ==============================================================================
# 1. CFF CONTAINER PACK / UNPACK ENGINE (Supports SpellForce 1 & 2 Databases)
# ==============================================================================


def unpack_cff(input_file, out_dir):
    """Unpacks a .cff archive container into separate .dat chunks (Supports SF1 & SF2 formats)."""
    print(f"[*] Unpacking CFF: {input_file} -> {out_dir}")
    os.makedirs(out_dir, exist_ok=True)

    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return False

    if len(data) < 20:
        print("[!] Error: File too small to be a CFF container!")
        return False

    # Detect format version via magic signature and header heuristics
    sig = data[0:4]
    if sig == b"\x02\xc5r\xdd":
        fmt_type = "sf1"
        print("[*] Detected SpellForce 1 CFF container (Original).")
    elif sig == b"\x12\xdd\x72\xdd":
        h2, h3, h4, h5 = struct.unpack_from("<IIII", data, 4)
        if h2 == 2 and h3 == 2 and h4 == 1 and h5 == 0:
            fmt_type = "sf1"
            print("[*] Detected SpellForce 1 CFF container (Platinum Edition).")
        else:
            if len(data) > 36:
                _, _, cs_2, _, us_2 = struct.unpack_from("<IHIHI", data, 20)
                if cs_2 == 0 and us_2 > len(data):
                    fmt_type = "sf1"
                    print("[*] Detected SpellForce 1 CFF container (Heuristic Match).")
                else:
                    fmt_type = "sf2"
                    print("[*] Detected SpellForce 2 CFF container.")
            else:
                fmt_type = "sf2"
                print("[*] Detected SpellForce 2 CFF container.")
    else:
        print(f"[!] Error: Invalid CFF signature! (Found: {sig.hex()})")
        return False

    with open(os.path.join(out_dir, "header.bin"), "wb") as f:
        f.write(data[0:20])

    manifest = {"format": fmt_type, "chunks": []}
    offset = 20
    chunk_idx = 0

    while offset < len(data):
        if fmt_type == "sf1":
            if offset + 12 > len(data):
                break
            c_id, occurrence, comp_flag, comp_size, c_type = struct.unpack_from(
                "<hhhih", data, offset
            )
            offset += 12

            if comp_flag == 0:
                uncomp_data = data[offset : offset + comp_size]
                offset += comp_size
            else:
                if offset + 4 > len(data):
                    break
                uncomp_size = struct.unpack_from("<i", data, offset)[0]
                offset += 4
                comp_data = data[offset : offset + comp_size]
                offset += comp_size
                try:
                    uncomp_data = zlib.decompress(comp_data)
                except Exception as e:
                    print(f"[!] Error decompressing SF1 chunk {chunk_idx}: {e}")
                    uncomp_data = comp_data

            chunk_name = f"chunk_{chunk_idx}.dat"
            with open(os.path.join(out_dir, chunk_name), "wb") as f:
                f.write(uncomp_data)

            manifest["chunks"].append(
                {
                    "file": chunk_name,
                    "id": c_id,
                    "occurrence": occurrence,
                    "comp_flag": comp_flag,
                    "type": c_type,
                }
            )
        else:  # sf2
            if offset + 16 > len(data):
                break
            c_id, flag1, comp_size, flag2, uncomp_size = struct.unpack_from(
                "<IHIHI", data, offset
            )
            offset += 16
            comp_data = data[offset : offset + comp_size]
            offset += comp_size

            try:
                uncomp_data = zlib.decompress(comp_data)
            except Exception as e:
                print(f"[!] Error decompressing SF2 chunk {chunk_idx}: {e}")
                uncomp_data = comp_data

            chunk_name = f"chunk_{chunk_idx}.dat"
            with open(os.path.join(out_dir, chunk_name), "wb") as f:
                f.write(uncomp_data)

            manifest["chunks"].append(
                {"file": chunk_name, "id": c_id, "flag1": flag1, "flag2": flag2}
            )
        chunk_idx += 1

    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=4)

    print("[+] Container unpacking completed!")
    return True


def pack_cff(input_dir, out_file, comp_level=6):
    """Packs raw .dat chunks back into a unified .cff container."""
    manifest_path = os.path.join(input_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        print("[!] Error: manifest.json not found in working directory!")
        return False

    if os.path.exists(out_file):
        bak_file = out_file + ".bak"
        print(f"[*] Creating backup of original file: {os.path.basename(bak_file)}")
        shutil.copy2(out_file, bak_file)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    fmt_type = manifest.get("format", "sf2")
    print(
        f"[*] Packing CFF ({fmt_type.upper()}) (compression level: {comp_level}): {input_dir} -> {out_file}"
    )

    with open(out_file, "wb") as out:
        header_path = os.path.join(input_dir, "header.bin")
        if os.path.exists(header_path):
            with open(header_path, "rb") as hf:
                out.write(hf.read())
        else:
            if fmt_type == "sf1":
                out.write(struct.pack("<i4i", -579674862, 0, 0, 0, 0))
            else:
                out.write(b"\x12\xdd\x72\xdd" + b"\x00" * 16)

        for chunk in manifest["chunks"]:
            chunk_file_path = os.path.join(input_dir, chunk["file"])
            if not os.path.exists(chunk_file_path):
                print(f"[!] Warning: Chunk file '{chunk['file']}' not found! Skipping.")
                continue

            with open(chunk_file_path, "rb") as cf:
                uncomp_data = cf.read()

            if fmt_type == "sf1":
                comp_flag = chunk.get("comp_flag", 1)
                occurrence = chunk.get("occurrence", 0)
                c_type = chunk.get("type", 0)

                if comp_flag == 0:
                    out.write(
                        struct.pack(
                            "<hhhih",
                            chunk["id"],
                            occurrence,
                            0,
                            len(uncomp_data),
                            c_type,
                        )
                    )
                    out.write(uncomp_data)
                else:
                    comp_data = zlib.compress(uncomp_data, level=comp_level)
                    out.write(
                        struct.pack(
                            "<hhhih",
                            chunk["id"],
                            occurrence,
                            comp_flag,
                            len(comp_data),
                            c_type,
                        )
                    )
                    out.write(struct.pack("<i", len(uncomp_data)))
                    out.write(comp_data)
            else:
                flag1 = chunk.get("flag1", 0)
                flag2 = chunk.get("flag2", 0)
                comp_data = zlib.compress(uncomp_data, level=comp_level)
                out.write(
                    struct.pack(
                        "<IHIHI",
                        chunk["id"],
                        flag1,
                        len(comp_data),
                        flag2,
                        len(uncomp_data),
                    )
                )
                out.write(comp_data)

    print("[+] Container packing completed!")
    return True


# ==============================================================================
# 2. CFF FORMAT DETECTOR & TEXT TRANSLATION EXPORTER
# ==============================================================================


def detect_format(data):
    """Detects CFF format schemas (Format A, B, C, Fixed_566 or pure binary)."""
    if len(data) < 8:
        return "binary", 0, 0

    if len(data) >= 566 and len(data) % 566 == 0:
        is_f566 = True
        for i in range(min(5, len(data) // 566)):
            if data[i * 566 + 565] != 0:
                is_f566 = False
                break
        if is_f566:
            return "fixed_566", 0, 0

    count = struct.unpack_from("<I", data, 0)[0]
    if count == 0 or count > 200000:
        return "binary", 0, 0

    try:
        offset = 4
        is_c = True
        for _ in range(count):
            if offset + 6 > len(data):
                is_c = False
                break
            marker = data[offset]
            if marker != 0x02:
                is_c = False
                break
            offset += 6
            if offset + 4 > len(data):
                is_c = False
                break
            name_len = struct.unpack_from("<I", data, offset)[0]
            if name_len > 100000 or offset + 4 + name_len > len(data):
                is_c = False
                break
            offset += 4 + name_len
            if offset + 4 > len(data):
                is_c = False
                break
            key_len = struct.unpack_from("<I", data, offset)[0]
            if key_len > 1000 or offset + 4 + key_len > len(data):
                is_c = False
                break
            offset += 4 + key_len
        if is_c and offset == len(data):
            return "developer_table", 0, 0
    except Exception:
        pass

    try:
        offset = 4
        is_a = True
        for _ in range(count):
            if offset + 5 > len(data):
                is_a = False
                break
            flag = data[offset]
            if flag != 0x01:
                is_a = False
                break
            offset += 1
            key_len = struct.unpack_from("<I", data, offset)[0]
            if key_len > 1000 or offset + 4 + key_len > len(data):
                is_a = False
                break
            offset += 4 + key_len
            if offset + 4 > len(data):
                is_a = False
                break
            text_len = struct.unpack_from("<I", data, offset)[0]
            if text_len > 100000 or offset + 4 + text_len * 2 > len(data):
                is_a = False
                break
            offset += 4 + text_len * 2
        if is_a and offset == len(data):
            return "string_table", 0, 0
    except Exception:
        pass

    for E in range(17):
        for N in range(1, 6):
            try:
                offset = 4
                is_b = True
                for _ in range(count):
                    if offset + 4 + E > len(data):
                        is_b = False
                        break
                    offset += 4 + E
                    for _ in range(N):
                        if offset + 4 > len(data):
                            is_b = False
                            break
                        str_len = struct.unpack_from("<I", data, offset)[0]
                        if str_len > 100000 or offset + 4 + str_len * 2 > len(data):
                            is_b = False
                            break
                        offset += 4 + str_len * 2
                if is_b and offset == len(data):
                    return "table_based", N, E
            except Exception:
                pass

    return "binary", 0, 0


def export_text(chunk_path, json_path):
    """Extracts text structures from standard or developer chunks to JSON."""
    with open(chunk_path, "rb") as f:
        data = f.read()

    if len(data) < 4:
        return False

    fmt, num_strings, extra_bytes = detect_format(data)
    if fmt == "binary":
        return False

    print(
        f"[*] Exporting text: {os.path.basename(chunk_path)} -> {os.path.basename(json_path)} | format: {fmt}"
    )
    texts = {}

    if fmt == "fixed_566":
        offset = 0
        while offset + 566 <= len(data):
            block = data[offset : offset + 566]
            str_id = struct.unpack_from("<I", block, 0)[0]
            text_bytes = block[54:566]
            null_idx = text_bytes.find(b"\x00")
            if null_idx != -1:
                text_bytes = text_bytes[:null_idx]

            try:
                text = text_bytes.decode("cp1252")
            except Exception:
                text = text_bytes.decode("cp1251", errors="ignore")

            texts[f"f566_{offset}_{str_id}"] = text
            offset += 566

    else:
        count = struct.unpack_from("<I", data, 0)[0]
        offset = 4

        if fmt == "string_table":
            for _ in range(count):
                if offset >= len(data):
                    break
                offset += 1
                key_len = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                key = data[offset : offset + key_len].decode("utf-8", errors="ignore")
                offset += key_len
                text_len = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                text = data[offset : offset + (text_len * 2)].decode(
                    "utf-16-le", errors="ignore"
                )
                offset += text_len * 2
                texts[key] = text

        elif fmt == "developer_table":
            for i in range(count):
                if offset >= len(data):
                    break
                offset += 1
                id_val = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                flag = data[offset]
                offset += 1
                name_len = struct.unpack_from("<I", data, offset)[0]
                offset += 4

                name_bytes = data[offset : offset + name_len]
                try:
                    name = name_bytes.decode("cp1252")
                except Exception:
                    name = name_bytes.decode("cp1251", errors="ignore")

                offset += name_len
                key_len = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                key = data[offset : offset + key_len].decode("cp1252", errors="ignore")
                offset += key_len
                texts[f"{i}_{id_val}_{flag}_{key}"] = name

        else:
            for i in range(count):
                if offset >= len(data):
                    break
                id_val = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                param_bytes = b""
                if extra_bytes > 0:
                    param_bytes = data[offset : offset + extra_bytes]
                    offset += extra_bytes
                extra_hex = param_bytes.hex()
                for s in range(num_strings):
                    if offset + 4 > len(data):
                        break
                    str_len = struct.unpack_from("<I", data, offset)[0]
                    offset += 4
                    text = data[offset : offset + str_len * 2].decode(
                        "utf-16-le", errors="ignore"
                    )
                    offset += str_len * 2
                    texts[f"{i}_{id_val}_{extra_hex}_str{s}"] = text

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(texts, f, indent=4, ensure_ascii=False)
    return True


def import_text(json_path, chunk_path):
    """Compiles edited JSONs back to CFF database binary formats."""
    print(
        f"[*] Importing text: {os.path.basename(json_path)} -> {os.path.basename(chunk_path)}"
    )
    with open(json_path, "r", encoding="utf-8") as f:
        texts = json.load(f)

    if not texts:
        return

    is_table_based = False
    is_developer_table = False
    is_fixed_566 = False
    num_strings = 0

    first_key = next(iter(texts.keys()), None)
    if first_key is not None:
        if first_key.startswith("f566_"):
            is_fixed_566 = True
        elif "_" in first_key:
            parts = first_key.split("_", 3)
            if len(parts) == 4 and parts[0].isdigit() and parts[1].isdigit():
                if parts[3].startswith("str"):
                    is_table_based = True
                    max_str_idx = 0
                    for key in texts.keys():
                        k_parts = key.split("_", 3)
                        if len(k_parts) == 4 and k_parts[3].startswith("str"):
                            str_idx = int(k_parts[3][3:])
                            if str_idx > max_str_idx:
                                max_str_idx = str_idx
                    num_strings = max_str_idx + 1
                else:
                    is_developer_table = True

    if is_fixed_566:
        with open(chunk_path, "rb") as f:
            orig_data = bytearray(f.read())

        for key, val in texts.items():
            if not key.startswith("f566_"):
                continue
            parts = key.split("_")
            offset = int(parts[1])

            try:
                text_bytes = val.encode("cp1252")
            except UnicodeEncodeError:
                text_bytes = val.encode("cp1251", errors="ignore")

            if len(text_bytes) > 511:
                text_bytes = text_bytes[:511]

            padded = text_bytes.ljust(512, b"\x00")
            if offset + 566 <= len(orig_data):
                orig_data[offset + 54 : offset + 566] = padded

        with open(chunk_path, "wb") as f:
            f.write(orig_data)
        print("[+] Text compiled to binary chunk (Fixed 566)!")
        return

    with open(chunk_path, "wb") as f:
        if not is_table_based and not is_developer_table:
            f.write(struct.pack("<I", len(texts)))
            for key, text in texts.items():
                f.write(b"\x01")
                kb = key.encode("utf-8")
                f.write(struct.pack("<I", len(kb)))
                f.write(kb)
                tb = text.encode("utf-16-le")
                f.write(struct.pack("<I", len(tb) // 2))
                f.write(tb)

        elif is_developer_table:
            entries = {}
            for key, val in texts.items():
                parts = key.split("_", 3)
                idx = int(parts[0])
                id_val = int(parts[1])
                flag = int(parts[2])
                dev_key = parts[3]
                entries[idx] = {
                    "id": id_val,
                    "flag": flag,
                    "name": val,
                    "key": dev_key,
                }
            sorted_indices = sorted(entries.keys())
            f.write(struct.pack("<I", len(sorted_indices)))
            for idx in sorted_indices:
                entry = entries[idx]
                f.write(struct.pack("<B", 0x02))
                f.write(struct.pack("<I", entry["id"]))
                f.write(struct.pack("<B", entry["flag"]))

                try:
                    name_bytes = entry["name"].encode("cp1252")
                except UnicodeEncodeError:
                    name_bytes = entry["name"].encode("cp1251", errors="ignore")

                f.write(struct.pack("<I", len(name_bytes)))
                f.write(name_bytes)
                key_bytes = entry["key"].encode("cp1252", errors="ignore")
                f.write(struct.pack("<I", len(key_bytes)))
                f.write(key_bytes)
        else:
            entries = {}
            for key, val in texts.items():
                parts = key.split("_", 3)
                idx = int(parts[0])
                id_val = int(parts[1])
                extra_hex = parts[2]
                field = parts[3]
                str_idx = int(field[3:])
                if idx not in entries:
                    entries[idx] = {
                        "id": id_val,
                        "extra_bytes": bytes.fromhex(extra_hex),
                        "strings": {},
                    }
                entries[idx]["strings"][str_idx] = val

            sorted_indices = sorted(entries.keys())
            f.write(struct.pack("<I", len(sorted_indices)))
            for idx in sorted_indices:
                entry = entries[idx]
                id_val = entry["id"]
                extra_bytes = entry["extra_bytes"]
                f.write(struct.pack("<I", id_val))
                if extra_bytes:
                    f.write(extra_bytes)
                for s in range(num_strings):
                    text_val = entry["strings"].get(s, "")
                    text_bytes = text_val.encode("utf-16-le")
                    f.write(struct.pack("<I", len(text_bytes) // 2))
                    f.write(text_bytes)

    print("[+] Text compiled to binary chunk!")


def unpack_all(cff_path, work_dir):
    """Complete batch extraction cycle: unpacks container and converts all text chunks to JSON."""
    print(f"[*] Starting full unpack cycle: {cff_path} -> {work_dir}")
    if not unpack_cff(cff_path, work_dir):
        return

    json_dir = os.path.join(work_dir, "texts_json")
    os.makedirs(json_dir, exist_ok=True)

    extracted_count = 0
    skipped_count = 0

    for file in os.listdir(work_dir):
        if file.startswith("chunk_") and file.endswith(".dat"):
            chunk_path = os.path.join(work_dir, file)
            try:
                chunk_idx = int(file.split("_")[1].split(".")[0])
            except Exception:
                continue

            with open(chunk_path, "rb") as f:
                data = f.read()

            if len(data) < 8:
                skipped_count += 1
                continue

            fmt, num_strings, extra_bytes = detect_format(data)

            if fmt == "binary":
                skipped_count += 1
                continue

            desc_name = f"chunk_{chunk_idx}_strings.json"
            json_path = os.path.join(json_dir, desc_name)

            if export_text(chunk_path, json_path):
                extracted_count += 1
            else:
                skipped_count += 1

    print(
        f"[+] Unpack completed! Exported: {extracted_count} text chunks, Skipped: {skipped_count} binary/empty chunks."
    )


def pack_all(work_dir, cff_path, comp_level=6):
    """Complete batch packing cycle: validates, compiles edited JSONs, and builds the CFF archive."""
    print(
        f"[*] Starting full pack cycle (compression: {comp_level}): {work_dir} -> {cff_path}"
    )
    json_dir = os.path.join(work_dir, "texts_json")

    if not os.path.exists(json_dir):
        print("[!] Error: texts_json directory not found inside the working directory!")
        return

    has_errors = False
    for file in os.listdir(json_dir):
        if file.endswith(".json"):
            json_path = os.path.join(json_dir, file)
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    json.load(f)
            except json.JSONDecodeError as je:
                print(f"[!] Critical JSON syntax error in '{file}': {je}")
                has_errors = True

    if has_errors:
        print(
            "[!] Packing aborted! Please fix the JSON formatting errors mentioned above."
        )
        return

    for file in os.listdir(json_dir):
        if file.endswith(".json"):
            json_path = os.path.join(json_dir, file)
            match = re.match(r"^chunk_(\d+)", file)
            if not match:
                continue
            chunk_idx = int(match.group(1))
            chunk_file = f"chunk_{chunk_idx}.dat"
            chunk_path = os.path.join(work_dir, chunk_file)

            if os.path.exists(chunk_path):
                import_text(json_path, chunk_path)
            else:
                print(
                    f"[!] Warning: missing base DAT chunk for {file}, cannot compile."
                )

    pack_cff(work_dir, cff_path, comp_level)
    print("[+] Localized CFF archive compiled successfully!")


# ==============================================================================
# 3. BINARY SCANNER (Visual Database Explorer Offset Finder)
# ==============================================================================


def scan_printable_strings(file_path, min_len=4):
    """Scans binary chunks for plain printable ASCII strings and asset paths."""
    if not os.path.exists(file_path):
        return []
    with open(file_path, "rb") as f:
        data = f.read()

    results = []
    current_str = []
    start_offset = None

    for i, b in enumerate(data):
        if 32 <= b <= 126:
            if start_offset is None:
                start_offset = i
            current_str.append(chr(b))
        else:
            if start_offset is not None:
                if len(current_str) >= min_len:
                    results.append((start_offset, "".join(current_str)))
                current_str = []
                start_offset = None

    if start_offset is not None and len(current_str) >= min_len:
        results.append((start_offset, "".join(current_str)))

    return results


# ==============================================================================
# 4. SPELLFORCE 1 & 2 .PAK ARCHIVE COMPILER ENGINE (Ported from C# PakTool)
# ==============================================================================


class BSTNode:
    def __init__(self, index, path, name):
        self.index = index
        self.path = path
        self.name = name
        self.left_idx = 0
        self.right_idx = 0
        self.boundary_flag = 0


def build_bounded_bst(nodes, start_idx, end_idx, max_jump=255):
    """
    Builds a search tree guaranteeing that the index distance between
    a parent node and any of its children does not exceed max_jump (255).
    """
    if start_idx > end_idx:
        return None

    mid = (start_idx + end_idx) // 2
    root = nodes[mid]

    left_start = start_idx
    if mid - left_start > max_jump:
        left_start = mid - max_jump

    right_end = end_idx
    if right_end - mid > max_jump:
        right_end = mid + max_jump

    left_child = build_bounded_bst(nodes, left_start, mid - 1, max_jump)
    right_child = build_bounded_bst(nodes, mid + 1, right_end, max_jump)

    if left_child:
        root.left_idx = left_child.index
    if right_child:
        root.right_idx = right_child.index

    return root


def read_reversed_string_sf1_from_bytes(data, offset, name_list_start):
    pos = name_list_start + offset
    chars = []
    while pos < len(data) and data[pos] != 0:
        chars.append(data[pos])
        pos += 1
    chars.reverse()
    return bytes(chars).decode("latin1", errors="ignore")


def read_pak_entries(pak_path):
    """Reads the file index from either a SpellForce 1 or SpellForce 2 .pak archive."""
    if not os.path.exists(pak_path):
        raise FileNotFoundError(f"File not found: {pak_path}")

    with open(pak_path, "rb") as fs:
        fs.seek(0, 2)
        total_len = fs.tell()
        if total_len >= 28:
            fs.seek(0)
            first_int = struct.unpack("<I", fs.read(4))[0]
            if first_int == 4:
                magic_bytes = fs.read(24)
                if magic_bytes.startswith(b"MASSIVE PAKFILE"):
                    fs.seek(76)
                    num_files, _, data_start, archive_size = struct.unpack(
                        "<IIII", fs.read(16)
                    )
                    fs.seek(92)
                    file_entries = []
                    for _ in range(num_files):
                        size, offset, name_off, dir_off = struct.unpack(
                            "<IIII", fs.read(16)
                        )
                        file_entries.append(
                            {
                                "size": size,
                                "offset": offset,
                                "name_off": name_off & 0x00FFFFFF,
                                "dir_off": dir_off & 0x00FFFFFF,
                                "name_off_raw": name_off,
                                "dir_off_raw": dir_off,
                            }
                        )

                    name_list_start = fs.tell()
                    entries = []

                    for entry in file_entries:
                        fs.seek(name_list_start + entry["name_off"])
                        prefix_bytes = fs.read(2)
                        prefix_hex = prefix_bytes.hex()

                        file_name = read_reversed_string_sf1(
                            fs, entry["name_off"] + 2, name_list_start
                        )
                        dir_name = ""
                        if (
                            entry["dir_off"] != 0x00FFFFFF
                            and entry["dir_off"] != 0xFFFFFF
                        ):
                            dir_name = read_reversed_string_sf1(
                                fs, entry["dir_off"], name_list_start
                            )

                        full_path = (
                            file_name if not dir_name else dir_name + "\\" + file_name
                        )
                        full_path = full_path.replace("/", "\\")

                        dir_flag = (entry["dir_off_raw"] >> 24) & 0xFF

                        entries.append(
                            {
                                "name": full_path,
                                "offset": data_start + entry["offset"],
                                "size": int(entry["size"]),
                                "prefix": prefix_hex,
                                "dir_flag": dir_flag,
                            }
                        )
                    return "sf1", entries

        # Fallback to SpellForce 2 PAK parsing
        fs.seek(0)
        magic = fs.read(3).decode("ascii", errors="ignore")
        if magic != "PAK":
            raise ValueError("Not a valid SpellForce PAK archive!")

        version = fs.read(1)[0]
        if version != 1:
            raise ValueError(f"Unknown PAK version: {version}")

        dir_offset, uncomp_size, comp_size = struct.unpack("<III", fs.read(12))

        fs.seek(dir_offset)
        comp_data = fs.read(comp_size)
        uncomp_data = zlib.decompress(comp_data)

        offset = 0
        file_count = struct.unpack_from("<i", uncomp_data, offset)[0]
        offset += 4

        entries = []
        for _ in range(file_count):
            name_len = struct.unpack_from("<i", uncomp_data, offset)[0]
            offset += 4
            name_bytes = uncomp_data[offset : offset + name_len]
            name = name_bytes.decode("latin1", errors="ignore")
            offset += name_len

            f_offset, next_offset = struct.unpack_from("<II", uncomp_data, offset)
            offset += 8

            entries.append(
                {"name": name, "offset": f_offset, "size": int(next_offset - f_offset)}
            )

        return "sf2", entries


def read_reversed_string_sf1(fs, offset, name_list_start):
    """Reads a reversed Latin1 string from the SpellForce 1 namelist offset."""
    orig_pos = fs.tell()
    fs.seek(name_list_start + offset)
    chars = []
    while True:
        b = fs.read(1)
        if not b or b[0] == 0:
            break
        chars.append(b[0])
    chars.reverse()
    fs.seek(orig_pos)
    return bytes(chars).decode("latin1", errors="ignore")


def unpack_pak(pak_path, out_dir, progress_callback=None):
    """Unpacks all files from a SpellForce 1 or 2 .pak archive to the specified directory."""
    res = read_pak_entries(pak_path)
    fmt = res[0]
    entries = res[1]

    os.makedirs(out_dir, exist_ok=True)

    if fmt == "sf1":
        with open(pak_path, "rb") as f:
            f.seek(84)
            data_start = struct.unpack("<I", f.read(4))[0]
            f.seek(0)
            meta_bytes = f.read(data_start)

        meta_path = os.path.join(out_dir, ".sf1_meta.bin")
        with open(meta_path, "wb") as mf:
            mf.write(meta_bytes)

    with open(pak_path, "rb") as fs:
        for idx, entry in enumerate(entries):
            name = entry["name"]
            if progress_callback:
                progress_callback(f"Extracting ({idx + 1}/{len(entries)}): {name}")

            clean_name = name.replace("\\", os.sep).replace("/", os.sep)
            target_path = os.path.join(out_dir, clean_name)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            fs.seek(entry["offset"])
            remaining = entry["size"]
            with open(target_path, "wb") as out_f:
                while remaining > 0:
                    chunk_size = min(65536, remaining)
                    buf = fs.read(chunk_size)
                    if not buf:
                        break
                    out_f.write(buf)
                    remaining -= len(buf)

    if progress_callback:
        progress_callback("Unpack complete!")


def pack_pak_sf2(source_dir, out_pak_path, comp_level=6, progress_callback=None):
    """Assembles and compresses files into a SpellForce 2 format .pak archive."""
    files = []
    for root, _, filenames in os.walk(source_dir):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    with open(out_pak_path, "wb") as fs:
        fs.write(b"PAK\x01")
        fs.write(struct.pack("<III", 0, 0, 0))

        entries = []
        for idx, file_path in enumerate(files):
            rel_path = (
                os.path.relpath(file_path, source_dir)
                .replace("/", "\\")
                .replace(os.sep, "\\")
                .lower()
            )
            if progress_callback:
                progress_callback(f"Packing ({idx + 1}/{len(files)}): {rel_path}")

            offset = fs.tell()
            with open(file_path, "rb") as in_f:
                shutil.copyfileobj(in_f, fs)

            entries.append(
                {"name": rel_path, "offset": offset, "size": fs.tell() - offset}
            )

        dir_offset = fs.tell()

        dir_buf = bytearray()
        dir_buf.extend(struct.pack("<i", len(entries)))
        for entry in entries:
            name_bytes = entry["name"].encode("latin1", errors="ignore")
            dir_buf.extend(struct.pack("<i", len(name_bytes)))
            dir_buf.extend(name_bytes)
            dir_buf.extend(
                struct.pack("<II", entry["offset"], entry["offset"] + entry["size"])
            )

        uncomp_size = len(dir_buf)
        comp_data = zlib.compress(dir_buf, level=comp_level)
        comp_size = len(comp_data)

        fs.write(comp_data)

        fs.seek(4)
        fs.write(struct.pack("<III", dir_offset, uncomp_size, comp_size))

    if progress_callback:
        progress_callback("Pack complete!")


def pack_pak_sf1(source_dir, out_pak_path, progress_callback=None):
    """
    Assembles files into a legacy SpellForce 1 format .pak archive using Meta-Template Injection.
    Safely preserves the original binary search tree logic and recalculates proper CRC32 hashes.
    """
    meta_path = os.path.join(source_dir, ".sf1_meta.bin")
    if not os.path.exists(meta_path):
        raise Exception(
            "ERROR: '.sf1_meta.bin' not found! You must unpack an existing SF1 archive "
            "with this exact tool first to preserve its internal binary search tree."
        )

    with open(meta_path, "rb") as f:
        meta_bytes = bytearray(f.read())

    num_files = struct.unpack_from("<I", meta_bytes, 76)[0]
    data_start = struct.unpack_from("<I", meta_bytes, 84)[0]
    name_list_start = 92 + num_files * 16

    entries = []
    for i in range(num_files):
        offset_in_meta = 92 + i * 16
        _, _, name_off, dir_off = struct.unpack_from(
            "<IIII", meta_bytes, offset_in_meta
        )

        file_name = read_reversed_string_sf1_from_bytes(
            meta_bytes, (name_off & 0x00FFFFFF) + 2, name_list_start
        )
        dir_name = ""
        d_off = dir_off & 0x00FFFFFF
        if d_off != 0x00FFFFFF and d_off != 0xFFFFFF:
            dir_name = read_reversed_string_sf1_from_bytes(
                meta_bytes, d_off, name_list_start
            )

        full_path = file_name if not dir_name else f"{dir_name}\\{file_name}"
        entries.append({"meta_offset": offset_in_meta, "name": full_path})

    payload = bytearray()
    for idx, entry in enumerate(entries):
        if progress_callback:
            progress_callback(f"Packing SF1 ({idx + 1}/{num_files}): {entry['name']}")

        file_path = os.path.join(source_dir, entry["name"].replace("\\", os.sep))
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                file_data = f.read()
        else:
            file_data = b""

        new_offset = len(payload)
        new_size = len(file_data)
        payload.extend(file_data)

        padding = (4 - (len(payload) % 4)) % 4
        if padding > 0:
            payload.extend(b"\x00" * padding)

        struct.pack_into("<I", meta_bytes, entry["meta_offset"], new_size)
        struct.pack_into("<I", meta_bytes, entry["meta_offset"] + 4, new_offset)

    total_size = data_start + len(payload)
    padding_total = (4096 - (total_size % 4096)) % 4096
    if padding_total > 0:
        payload.extend(b"\x00" * padding_total)
        total_size += padding_total

    struct.pack_into("<I", meta_bytes, 88, total_size)
    struct.pack_into("<I", meta_bytes, 72, 0xFFFFFFFF)

    header_92 = meta_bytes[:92]
    seed = calculate_sf1_crc(header_92)

    file_table_bytes = meta_bytes[92 : 92 + num_files * 16]
    file_table_crc = calculate_sf1_crc(file_table_bytes, seed)

    string_table_bytes = meta_bytes[92 + num_files * 16 : data_start]
    final_crc = calculate_sf1_crc(string_table_bytes, file_table_crc)

    struct.pack_into("<I", meta_bytes, 72, final_crc)

    with open(out_pak_path, "wb") as f:
        f.write(meta_bytes)
        f.write(payload)

    if progress_callback:
        progress_callback(
            f"[+] Pack complete! Archive Size: {total_size} bytes, Checksum: {hex(final_crc)}"
        )


def pack_pak_sf1_from_scratch(source_dir, out_pak_path, progress_callback=None):
    """
    Experimental: Compiles a SpellForce 1 .PAK archive from scratch.
    NOTE: The SF1 game engine utilizes proprietary directory occurrence counters (hash buckets)
    encoded in the high bytes of offsets. This function successfully builds an archive with
    a perfect CRC32, but it WILL FAIL TO LOAD IN-GAME due to these missing undocumented hash indices.
    Please use the Meta-Template Injection mode for actual game modding.
    """
    if progress_callback:
        progress_callback(
            "[!] WARNING: 'From Scratch' mode is highly experimental for SF1."
        )
        progress_callback("[*] Scanning source directory for files...")

    all_items = []
    for root, _, filenames in os.walk(source_dir):
        for filename in filenames:
            if filename == ".sf1_meta.bin" or filename.startswith("."):
                continue
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, source_dir).replace("/", "\\")
            all_items.append(rel_path)

    all_items.sort(key=lambda x: x[::-1])
    num_files = len(all_items)

    if progress_callback:
        progress_callback(f"[+] Found {num_files} files for packing.")

    nodes = []
    for idx, path in enumerate(all_items):
        file_name = os.path.basename(path)
        nodes.append(BSTNode(idx, path, file_name))

    dir_groups = {}
    for node in nodes:
        dir_path = os.path.dirname(node.path)
        if dir_path not in dir_groups:
            dir_groups[dir_path] = []
        dir_groups[dir_path].append(node)

    for dir_path, group_nodes in dir_groups.items():
        group_nodes[0].boundary_flag = 1
        build_bounded_bst(group_nodes, 0, len(group_nodes) - 1, max_jump=255)

    string_table = bytearray()
    string_offsets = {}

    unique_dirs = sorted(list(dir_groups.keys()))
    for d in unique_dirs:
        if d == "":
            continue
        rev_d = d.encode("latin1", errors="ignore")[::-1] + b"\x00"
        string_offsets[d] = len(string_table)
        string_table.extend(rev_d)

    for node in nodes:
        rev_name = node.name.encode("latin1", errors="ignore")[::-1] + b"\x00"
        node_offset = len(string_table)
        string_offsets[node.path] = node_offset

        left_val = (node.index - node.left_idx) if node.left_idx != 0 else 0
        right_val = (node.right_idx - node.index) if node.right_idx != 0 else 0

        prefix = bytes([left_val & 0xFF, right_val & 0xFF])
        string_table.extend(prefix + rev_name)

    file_table = bytearray()
    payload = bytearray()

    current_dir = None

    for node in nodes:
        full_filepath = os.path.join(source_dir, node.path)
        try:
            with open(full_filepath, "rb") as f:
                file_data = f.read()
        except Exception as e:
            if progress_callback:
                progress_callback(
                    f"[!] Error reading file {node.path}: {e}. Writing empty file."
                )
            file_data = b""

        size = len(file_data)
        offset = len(payload)

        payload.extend(file_data)
        padding_size = (4 - (len(payload) % 4)) % 4
        payload.extend(b"\x00" * padding_size)

        name_off_raw = string_offsets[node.path]

        dir_path = os.path.dirname(node.path)
        if dir_path == "":
            dir_off_raw = 0x00FFFFFF
        else:
            dir_off_base = string_offsets[dir_path]
            b_flag = 0
            if dir_path != current_dir:
                b_flag = 1
                current_dir = dir_path
            dir_off_raw = dir_off_base | (b_flag << 24)

        file_table.extend(struct.pack("<IIII", size, offset, name_off_raw, dir_off_raw))

    root_node = build_bounded_bst(nodes, 0, num_files - 1, max_jump=255)
    root_idx = root_node.index if root_node else 0

    header_size = 92
    file_table_offset = header_size
    string_table_offset = file_table_offset + len(file_table)
    data_start_offset = string_table_offset + len(string_table)

    total_payload_size = len(payload)
    total_archive_size = data_start_offset + total_payload_size
    padding_total = (4096 - (total_archive_size % 4096)) % 4096
    payload.extend(b"\x00" * padding_total)
    total_archive_size += padding_total

    header = bytearray(92)
    struct.pack_into("<I", header, 0, 4)
    header[4:28] = b"MASSIVE PAKFILE V 4.0\r\n\x00"
    struct.pack_into("<I", header, 72, 0xFFFFFFFF)
    struct.pack_into("<I", header, 76, num_files)
    struct.pack_into("<I", header, 80, root_idx)
    struct.pack_into("<I", header, 84, data_start_offset)
    struct.pack_into("<I", header, 88, total_archive_size)

    if progress_callback:
        progress_callback("[*] Calculating custom IEEE 802.3 CRC32 checksum...")

    seed = calculate_sf1_crc(header)
    file_table_crc = calculate_sf1_crc(file_table, seed)
    final_crc = calculate_sf1_crc(string_table, file_table_crc)

    struct.pack_into("<I", header, 72, final_crc)

    if progress_callback:
        progress_callback(f"[*] Writing archive: {os.path.basename(out_pak_path)}")

    with open(out_pak_path, "wb") as out_f:
        out_f.write(header)
        out_f.write(file_table)
        out_f.write(string_table)
        out_f.write(payload)

    if progress_callback:
        progress_callback(f"[+] Pack from scratch complete! Checksum: {hex(final_crc)}")


def batch_unpack_paks(root_dir, progress_callback=None):
    """Finds all .pak files in root_dir recursively and unpacks them."""
    pak_files = []
    for root, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.lower().endswith(".pak"):
                pak_files.append(os.path.join(root, filename))

    if not pak_files:
        if progress_callback:
            progress_callback("[!] No .pak archives found to unpack in this directory!")
        return

    if progress_callback:
        progress_callback(
            f"[*] Found {len(pak_files)} archives. Starting batch unpack..."
        )

    for pak_path in pak_files:
        dir_name = os.path.dirname(pak_path)
        base_name = os.path.splitext(os.path.basename(pak_path))[0]
        out_dir = os.path.join(dir_name, base_name + "_extracted")

        if progress_callback:
            progress_callback(
                f"[*] Unpacking archive: {os.path.basename(pak_path)} -> {os.path.basename(out_dir)}"
            )
        try:
            unpack_pak(pak_path, out_dir, progress_callback)
        except Exception as e:
            if progress_callback:
                progress_callback(
                    f"[!] Error unpacking {os.path.basename(pak_path)}: {e}"
                )

    if progress_callback:
        progress_callback("[+] Batch unpack successfully finished!")


def batch_pack_folders(
    root_dir,
    fmt,
    comp_level=6,
    sf1_mode="Meta-Template (100% Stable)",
    progress_callback=None,
):
    """Finds all subfolders in root_dir and compiles them back to .pak archives."""
    if not os.path.exists(root_dir):
        if progress_callback:
            progress_callback("[!] Selected root directory does not exist!")
        return

    subdirs = [
        os.path.join(root_dir, d)
        for d in os.listdir(root_dir)
        if os.path.isdir(os.path.join(root_dir, d))
    ]
    if not subdirs:
        if progress_callback:
            progress_callback("[!] No subfolders found to pack inside this directory!")
        return

    if progress_callback:
        progress_callback(f"[*] Starting batch pack of {len(subdirs)} folders...")

    for subdir in subdirs:
        folder_name = os.path.basename(subdir)
        base_name = folder_name

        if folder_name.lower().endswith("_extracted"):
            base_name = folder_name[:-10]

        out_pak_path = os.path.join(root_dir, base_name + ".pak")

        if progress_callback:
            progress_callback(
                f"[*] Packing folder: {folder_name} -> {os.path.basename(out_pak_path)}"
            )
        try:
            if fmt == "sf1":
                if sf1_mode.startswith("Meta-Template"):
                    pack_pak_sf1(subdir, out_pak_path, progress_callback)
                else:
                    pack_pak_sf1_from_scratch(subdir, out_pak_path, progress_callback)
            else:
                pack_pak_sf2(subdir, out_pak_path, comp_level, progress_callback)
            if progress_callback:
                progress_callback(
                    f"[+] Successfully compiled: {os.path.basename(out_pak_path)}"
                )
        except Exception as e:
            if progress_callback:
                progress_callback(f"[!] Error packing folder {folder_name}: {e}")

    if progress_callback:
        progress_callback("[+] Batch pack successfully completed!")


# ==============================================================================
# 5. TABBED DESKTOP USER INTERFACE ENGINE (Tkinter)
# ==============================================================================


def launch_gui():
    """Launches the advanced graphical user interface with Chunk String Inspector."""
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title("SpellForce 1 & 2 - Complete Modding Suite")
    root.geometry("1020x720")
    root.configure(bg="#1E1E1E")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TNotebook", background="#1E1E1E", borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background="#333333",
        foreground="#FFFFFF",
        borderwidth=0,
        padding=[10, 5],
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", "#5A5A5A")],
        foreground=[("selected", "#FFFFFF")],
    )

    fg_color = "#ffffff"
    bg_color = "#1E1E1E"
    btn_color = "#333333"
    entry_color = "#2d2d2d"

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    tab_archive = tk.Frame(notebook, bg=bg_color)
    tab_inspector = tk.Frame(notebook, bg=bg_color)
    tab_log = tk.Frame(notebook, bg=bg_color)

    notebook.add(tab_archive, text=" Archive Tool ")
    notebook.add(tab_inspector, text=" Binary Chunk Inspector ")
    notebook.add(tab_log, text=" Progress Terminal ")

    # ================= TAB 3: PROGRESS TERMINAL =================
    log_frame = tk.LabelFrame(
        tab_log,
        text=" Active Logs & Progress Terminal ",
        font=("Arial", 10, "bold"),
        fg=fg_color,
        bg=bg_color,
        padx=5,
        pady=5,
    )
    log_frame.pack(fill="both", expand=True, padx=20, pady=10)

    text_log = tk.Text(
        log_frame,
        wrap="word",
        height=10,
        fg="#00ff00",
        bg="#121212",
        font=("Consolas", 10),
    )
    text_log.pack(fill="both", expand=True)

    log_queue = queue.Queue()

    class ThreadSafeLogger:
        def __init__(self, target_queue, original_stream=None):
            self.target_queue = target_queue
            self.original_stream = original_stream

        def write(self, message):
            self.target_queue.put(message)
            if self.original_stream:
                self.original_stream.write(message)

        def flush(self):
            if self.original_stream:
                self.original_stream.flush()

    def poll_log_queue():
        try:
            while True:
                msg = log_queue.get_nowait()
                text_log.insert(tk.END, msg)
                text_log.see(tk.END)
                log_queue.task_done()
        except queue.Empty:
            pass
        root.after(100, poll_log_queue)

    orig_stdout = sys.stdout
    orig_stderr = sys.stderr
    sys.stdout = ThreadSafeLogger(log_queue, orig_stdout)
    sys.stderr = ThreadSafeLogger(log_queue, orig_stderr)

    root.after(100, poll_log_queue)

    def run_thread(target):
        threading.Thread(target=target, daemon=True).start()

    # ================= TAB 1: ARCHIVE TOOL =================
    cff_var = tk.StringVar(value="")
    work_dir_var = tk.StringVar(value="work_folder")
    comp_level_var = tk.IntVar(value=6)
    pak_file_var = tk.StringVar(value="")
    pak_out_var = tk.StringVar(value="extracted_pak")
    pak_src_var = tk.StringVar(value="")
    pak_fmt_var = tk.StringVar(value="SpellForce 1 (.pak)")
    pak_comp_var = tk.IntVar(value=6)
    sf1_mode_var = tk.StringVar(value="Meta-Template (100% Stable)")
    status_msg_var = tk.StringVar(value="Ready.")

    pane_archive = tk.PanedWindow(tab_archive, orient="horizontal", bg=bg_color, bd=0)
    pane_archive.pack(fill="both", expand=True, padx=20, pady=5)

    left_control_col = tk.Frame(pane_archive, bg=bg_color)
    pane_archive.add(left_control_col, width=440)

    # Unpack Frame
    unpack_frame = tk.LabelFrame(
        left_control_col,
        text=" Unpack Existing .PAK ",
        font=("Arial", 10, "bold"),
        fg=fg_color,
        bg=bg_color,
        padx=15,
        pady=10,
    )
    unpack_frame.pack(fill="x", pady=5)

    tk.Label(unpack_frame, text="Source .PAK File:", fg=fg_color, bg=bg_color).grid(
        row=0, column=0, sticky="w", pady=5
    )
    tk.Entry(
        unpack_frame,
        textvariable=pak_file_var,
        width=25,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    ).grid(row=0, column=1, padx=5, pady=5)

    def select_pak_file():
        path = filedialog.askopenfilename(filetypes=[("PAK files", "*.pak")])
        if path:
            pak_file_var.set(path)
            try:
                res = read_pak_entries(path)
                fmt = res[0]
                entries = res[1]
                populate_tree_from_entries(
                    archive_tree, entries, os.path.basename(path)
                )
                fmt_name = "SpellForce 1" if fmt == "sf1" else "SpellForce 2"
                status_msg_var.set(
                    f"Opened {os.path.basename(path)}. Format: {fmt_name}. Found {len(entries)} files."
                )
            except Exception as ex:
                status_msg_var.set(f"Error reading index: {ex}")

    tk.Button(
        unpack_frame,
        text="Browse...",
        command=select_pak_file,
        fg=fg_color,
        bg=btn_color,
    ).grid(row=0, column=2, padx=5, pady=5)

    tk.Label(unpack_frame, text="Output Directory:", fg=fg_color, bg=bg_color).grid(
        row=1, column=0, sticky="w", pady=5
    )
    tk.Entry(
        unpack_frame,
        textvariable=pak_out_var,
        width=25,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    ).grid(row=1, column=1, padx=5, pady=5)

    def select_pak_out():
        path = filedialog.askdirectory()
        if path:
            pak_out_var.set(path)

    tk.Button(
        unpack_frame,
        text="Browse...",
        command=select_pak_out,
        fg=fg_color,
        bg=btn_color,
    ).grid(row=1, column=2, padx=5, pady=5)

    def on_unpack_pak():
        file_path = pak_file_var.get().strip()
        out_dir = pak_out_var.get().strip()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid .pak archive first!")
            return

        text_log.delete("1.0", tk.END)
        notebook.select(tab_log)
        run_thread(lambda: unpack_pak(file_path, out_dir, print))

    def gui_batch_unpack_pak():
        root_dir = filedialog.askdirectory(
            title="Select Root Folder containing .PAK archives"
        )
        if not root_dir:
            return

        text_log.delete("1.0", tk.END)
        notebook.select(tab_log)
        run_thread(lambda: batch_unpack_paks(root_dir, print))

    tk.Button(
        unpack_frame,
        text="Extract All",
        command=on_unpack_pak,
        fg=fg_color,
        bg="#1e5f1e",
        font=("Arial", 10, "bold"),
        padx=5,
        pady=3,
    ).grid(row=2, column=1, sticky="w", pady=10)

    tk.Button(
        unpack_frame,
        text="Batch Unpack...",
        command=gui_batch_unpack_pak,
        fg=fg_color,
        bg="#1e5f1e",
        font=("Arial", 10, "bold"),
        padx=5,
        pady=3,
    ).grid(row=2, column=2, sticky="w", pady=10, padx=5)

    # Pack Frame (PAK)
    pack_frame = tk.LabelFrame(
        left_control_col,
        text=" Pack Folder into .PAK ",
        font=("Arial", 10, "bold"),
        fg=fg_color,
        bg=bg_color,
        padx=15,
        pady=10,
    )
    pack_frame.pack(fill="x", pady=5)

    tk.Label(pack_frame, text="Source Folder:", fg=fg_color, bg=bg_color).grid(
        row=0, column=0, sticky="w", pady=5
    )
    tk.Entry(
        pack_frame,
        textvariable=pak_src_var,
        width=25,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    ).grid(row=0, column=1, padx=5, pady=5)

    def select_pak_src():
        path = filedialog.askdirectory()
        if path:
            pak_src_var.set(path)
            try:
                populate_tree_from_directory(archive_tree, path)
                status_msg_var.set(
                    f"Loaded folder: {os.path.basename(path)}. Ready to pack."
                )
            except Exception as ex:
                status_msg_var.set(f"Error loading folder: {ex}")

    tk.Button(
        pack_frame, text="Browse...", command=select_pak_src, fg=fg_color, bg=btn_color
    ).grid(row=0, column=2, padx=5, pady=5)

    tk.Label(pack_frame, text="Format Target:", fg=fg_color, bg=bg_color).grid(
        row=1, column=0, sticky="w", pady=5
    )

    sf1_mode_frame = tk.Frame(pack_frame, bg=bg_color)

    def on_fmt_change(event):
        if pak_fmt_cb.get() == "SpellForce 1 (.pak)":
            pak_scale.config(state="disabled", fg="#555555")
            sf1_mode_frame.grid(row=3, column=0, columnspan=3, sticky="w", pady=5)
        else:
            pak_scale.config(state="normal", fg=fg_color)
            sf1_mode_frame.grid_forget()

    pak_fmt_cb = ttk.Combobox(
        pack_frame,
        textvariable=pak_fmt_var,
        values=["SpellForce 1 (.pak)", "SpellForce 2 (.pak)"],
        state="readonly",
        width=22,
    )
    pak_fmt_cb.grid(row=1, column=1, sticky="w", pady=5, padx=5)
    pak_fmt_cb.bind("<<ComboboxSelected>>", on_fmt_change)

    tk.Label(pack_frame, text="Compression (0-9):", fg=fg_color, bg=bg_color).grid(
        row=2, column=0, sticky="w", pady=5
    )
    pak_scale = tk.Scale(
        pack_frame,
        from_=0,
        to=9,
        variable=pak_comp_var,
        orient="horizontal",
        fg=fg_color,
        bg=bg_color,
        highlightthickness=0,
        showvalue=True,
        width=15,
    )
    pak_scale.grid(row=2, column=1, sticky="ew", padx=5)

    # SF1 Packing Options
    tk.Label(sf1_mode_frame, text="Mode:", fg=fg_color, bg=bg_color).pack(
        side="left", padx=5
    )
    tk.Radiobutton(
        sf1_mode_frame,
        text="Meta-Template (100% Stable)",
        variable=sf1_mode_var,
        value="Meta-Template (100% Stable)",
        fg=fg_color,
        bg=bg_color,
        selectcolor=bg_color,
        activebackground=bg_color,
    ).pack(side="top", anchor="w")
    tk.Radiobutton(
        sf1_mode_frame,
        text="From Scratch (Experimental/Fails in Game)",
        variable=sf1_mode_var,
        value="From Scratch",
        fg="#b05050",
        bg=bg_color,
        selectcolor=bg_color,
        activebackground=bg_color,
    ).pack(side="top", anchor="w")

    # Align frame on default load
    sf1_mode_frame.grid(row=3, column=0, columnspan=3, sticky="w", pady=5)

    def on_pack_pak():
        src_dir = pak_src_var.get().strip()
        fmt_name = pak_fmt_var.get()
        level = pak_comp_var.get()
        sf1_mode = sf1_mode_var.get()

        if not src_dir or not os.path.exists(src_dir):
            messagebox.showerror("Error", "Please select a valid source folder first!")
            return

        out_file = filedialog.asksaveasfilename(
            defaultextension=".pak", filetypes=[("PAK files", "*.pak")]
        )
        if not out_file:
            return

        text_log.delete("1.0", tk.END)
        notebook.select(tab_log)

        def thread_pack():
            try:
                if fmt_name == "SpellForce 1 (.pak)":
                    if sf1_mode.startswith("Meta-Template"):
                        pack_pak_sf1(src_dir, out_file, print)
                    else:
                        pack_pak_sf1_from_scratch(src_dir, out_file, print)
                else:
                    pack_pak_sf2(src_dir, out_file, level, print)
            except Exception as e:
                print(f"\n[!] Build Error: {e}")

        run_thread(thread_pack)

    def gui_batch_pack_pak():
        root_dir = filedialog.askdirectory(
            title="Select Root Folder containing subfolders to pack"
        )
        if not root_dir:
            return

        fmt_name = pak_fmt_var.get()
        level = pak_comp_var.get()
        fmt = "sf1" if fmt_name == "SpellForce 1 (.pak)" else "sf2"
        sf1_mode = sf1_mode_var.get()

        text_log.delete("1.0", tk.END)
        notebook.select(tab_log)
        run_thread(lambda: batch_pack_folders(root_dir, fmt, level, sf1_mode, print))

    tk.Button(
        pack_frame,
        text="Pack Folder",
        command=on_pack_pak,
        fg=fg_color,
        bg="#5f1e1e",
        font=("Arial", 10, "bold"),
        padx=5,
        pady=3,
    ).grid(row=4, column=1, sticky="w", pady=10)

    tk.Button(
        pack_frame,
        text="Batch Pack...",
        command=gui_batch_pack_pak,
        fg=fg_color,
        bg="#5f1e1e",
        font=("Arial", 10, "bold"),
        padx=5,
        pady=3,
    ).grid(row=4, column=2, sticky="w", pady=10, padx=5)

    # CFF Container Tool
    cff_frame = tk.LabelFrame(
        left_control_col,
        text=" SpellForce 1 & 2 CFF Database Containers ",
        font=("Arial", 10, "bold"),
        fg=fg_color,
        bg=bg_color,
        padx=15,
        pady=10,
    )
    cff_frame.pack(fill="x", pady=5)

    tk.Label(cff_frame, text="CFF Container File:", fg=fg_color, bg=bg_color).grid(
        row=0, column=0, sticky="w", pady=5
    )
    tk.Entry(
        cff_frame,
        textvariable=cff_var,
        width=25,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    ).grid(row=0, column=1, padx=5, pady=5)

    def select_cff():
        path = filedialog.askopenfilename(filetypes=[("CFF files", "*.cff")])
        if path:
            cff_var.set(path)

    tk.Button(
        cff_frame,
        text="Browse...",
        command=select_cff,
        fg=fg_color,
        bg=btn_color,
        activebackground="#555555",
    ).grid(row=0, column=2, padx=5, pady=5)

    tk.Label(cff_frame, text="Working Directory:", fg=fg_color, bg=bg_color).grid(
        row=1, column=0, sticky="w", pady=5
    )
    tk.Entry(
        cff_frame,
        textvariable=work_dir_var,
        width=25,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    ).grid(row=1, column=1, padx=5, pady=5)

    def select_work_dir():
        path = filedialog.askdirectory()
        if path:
            work_dir_var.set(path)

    tk.Button(
        cff_frame,
        text="Browse...",
        command=select_work_dir,
        fg=fg_color,
        bg=btn_color,
        activebackground="#555555",
    ).grid(row=1, column=2, padx=5, pady=5)

    tk.Label(cff_frame, text="Zlib Compression (0-9):", fg=fg_color, bg=bg_color).grid(
        row=2, column=0, sticky="w", pady=5
    )
    tk.Scale(
        cff_frame,
        from_=0,
        to=9,
        variable=comp_level_var,
        orient="horizontal",
        fg=fg_color,
        bg=bg_color,
        highlightthickness=0,
        showvalue=True,
        width=15,
    ).grid(row=2, column=1, sticky="ew", padx=5)

    def gui_unpack():
        cff = cff_var.get()
        work = work_dir_var.get()
        if not cff or not os.path.exists(cff):
            messagebox.showerror("Error", "Please select a valid .cff file first!")
            return
        text_log.delete("1.0", tk.END)
        notebook.select(tab_log)
        run_thread(lambda: unpack_all(cff, work))

    def gui_pack():
        work = work_dir_var.get()
        level = comp_level_var.get()
        if not os.path.exists(work):
            messagebox.showerror("Error", "Working directory not found!")
            return
        cff = filedialog.asksaveasfilename(
            defaultextension=".cff", filetypes=[("CFF files", "*.cff")]
        )
        if not cff:
            return
        text_log.delete("1.0", tk.END)
        notebook.select(tab_log)
        run_thread(lambda: pack_all(work, cff, level))

    tk.Button(
        cff_frame,
        text="Unpack CFF",
        command=gui_unpack,
        fg=fg_color,
        bg="#1e5f1e",
        font=("Arial", 10, "bold"),
        padx=5,
        pady=3,
    ).grid(row=3, column=1, sticky="w", pady=10)

    tk.Button(
        cff_frame,
        text="Pack to CFF",
        command=gui_pack,
        fg=fg_color,
        bg="#5f1e1e",
        font=("Arial", 10, "bold"),
        padx=5,
        pady=3,
    ).grid(row=3, column=2, sticky="w", pady=10, padx=5)

    # Right Column: Expandable TreeView
    right_tree_col = tk.LabelFrame(
        pane_archive,
        text=" Archive Content Explorer ",
        font=("Arial", 10, "bold"),
        fg=fg_color,
        bg=bg_color,
        padx=10,
        pady=10,
    )
    pane_archive.add(right_tree_col, width=530)

    tree_scroll = tk.Scrollbar(right_tree_col, orient="vertical")
    tree_scroll.pack(side="right", fill="y")

    archive_tree_style = ttk.Style(root)
    archive_tree_style.configure(
        "Archive.Treeview",
        background="#1E1E1E",
        foreground="#FFFFFF",
        fieldbackground="#121212",
        rowheight=24,
        font=("Consolas", 10),
    )
    archive_tree_style.configure(
        "Archive.Treeview.Heading", background="#333333", foreground="#FFFFFF"
    )

    archive_tree = ttk.Treeview(
        right_tree_col,
        show="tree",
        yscrollcommand=tree_scroll.set,
        style="Archive.Treeview",
    )
    archive_tree.pack(fill="both", expand=True, side="left")
    tree_scroll.config(command=archive_tree.yview)

    def populate_tree_from_entries(tree_widget, entries, archive_name):
        for item in tree_widget.get_children():
            tree_widget.delete(item)

        root_id = tree_widget.insert("", "end", text=archive_name, open=True)
        nodes_dict = {"": root_id}

        for entry in entries:
            path = entry["name"]
            parts = re.split(r"[\\/]", path)

            current_path = ""
            parent_id = root_id

            for part in parts:
                new_path = part if not current_path else current_path + "\\" + part

                if new_path not in nodes_dict:
                    node_id = tree_widget.insert(
                        parent_id, "end", text=part, open=False
                    )
                    nodes_dict[new_path] = node_id

                parent_id = nodes_dict[new_path]
                current_path = new_path

    def populate_tree_from_directory(tree_widget, dir_path):
        for item in tree_widget.get_children():
            tree_widget.delete(item)

        root_name = os.path.basename(dir_path) or "Folder"
        root_id = tree_widget.insert("", "end", text=root_name, open=True)

        def recurse(parent_node, current_dir):
            try:
                for d in sorted(os.listdir(current_dir)):
                    full_path = os.path.join(current_dir, d)
                    if os.path.isdir(full_path):
                        node_id = tree_widget.insert(
                            parent_node, "end", text=d, open=False
                        )
                        recurse(node_id, full_path)

                for f in sorted(os.listdir(current_dir)):
                    full_path = os.path.join(current_dir, f)
                    if os.path.isfile(full_path):
                        tree_widget.insert(parent_node, "end", text=f, open=False)
            except Exception as e:
                print(f"[!] Error scanning directory: {e}")

        recurse(root_id, dir_path)

    # Status Bar
    status_bar = tk.Frame(tab_archive, bg="#2D2D30", height=30)
    status_bar.pack(fill="x", side="bottom", padx=20, pady=(5, 10))

    status_lbl = tk.Label(
        status_bar,
        textvariable=status_msg_var,
        font=("Arial", 10),
        fg="#4CAF50",
        bg="#2D2D30",
        anchor="w",
        padx=10,
        pady=5,
    )
    status_lbl.pack(fill="x")

    # ================= TAB 2: BINARY CHUNK INSPECTOR =================
    dat_var = tk.StringVar(value="")
    search_var = tk.StringVar(value="")
    selected_base_offset = tk.StringVar(value="N/A")
    rel_var = tk.StringVar(value="0")
    target_var = tk.StringVar(value="0")
    dtype_var = tk.StringVar(value="Int16 (short)")
    current_val_var = tk.StringVar(value="No File")
    new_val_var = tk.StringVar(value="")

    pane = tk.PanedWindow(tab_inspector, orient="horizontal", bg=bg_color, bd=0)
    pane.pack(fill="both", expand=True, padx=20, pady=5)

    left_frame = tk.Frame(pane, bg=bg_color)
    pane.add(left_frame, width=480)

    select_frame = tk.Frame(left_frame, bg=bg_color)
    select_frame.pack(fill="x", pady=2)

    tk.Label(select_frame, text="Chunk file:", fg=fg_color, bg=bg_color).grid(
        row=0, column=0, sticky="w"
    )
    tk.Entry(
        select_frame,
        textvariable=dat_var,
        width=40,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    ).grid(row=0, column=1, padx=5)

    def select_dat():
        path = filedialog.askopenfilename(filetypes=[("DAT chunk files", "*.dat")])
        if path:
            dat_var.set(path)
            trigger_scan()

    tk.Button(
        select_frame,
        text="Browse...",
        command=select_dat,
        fg=fg_color,
        bg=btn_color,
        activebackground="#555555",
    ).grid(row=0, column=2, padx=5)

    search_frame = tk.Frame(left_frame, bg=bg_color)
    search_frame.pack(fill="x", pady=2)

    tk.Label(search_frame, text="Filter Strings:", fg=fg_color, bg=bg_color).pack(
        side="left", padx=(0, 5)
    )
    search_entry = tk.Entry(
        search_frame,
        textvariable=search_var,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
        width=30,
    )
    search_entry.pack(side="left", fill="x", expand=True)

    tree_frame = tk.Frame(left_frame, bg="#121212")
    tree_frame.pack(fill="both", expand=True, pady=5)

    scrollbar = tk.Scrollbar(tree_frame, orient="vertical")
    scrollbar.pack(side="right", fill="y")

    tree_style = ttk.Style(root)
    tree_style.configure(
        "Custom.Treeview",
        background="#1E1E1E",
        foreground="#FFFFFF",
        fieldbackground="#121212",
        rowheight=24,
        font=("Consolas", 10),
    )
    tree_style.configure(
        "Custom.Treeview.Heading", background="#333333", foreground="#FFFFFF"
    )

    tree = ttk.Treeview(
        tree_frame,
        columns=("dec", "hex", "value"),
        show="headings",
        yscrollcommand=scrollbar.set,
        style="Custom.Treeview",
    )
    tree.heading("dec", text="Dec Offset")
    tree.heading("hex", text="Hex Offset")
    tree.heading("value", text="Printable ASCII / Asset Path String")

    tree.column("dec", width=85, anchor="center")
    tree.column("hex", width=85, anchor="center")
    tree.column("value", width=300, anchor="w")

    tree.pack(fill="both", expand=True, side="left")
    scrollbar.config(command=tree.yview)

    # Right Frame (Modifier)
    right_frame = tk.LabelFrame(
        pane,
        text=" Value Modifier & Hex Inspector ",
        font=("Arial", 10, "bold"),
        fg=fg_color,
        bg=bg_color,
        padx=10,
        pady=10,
    )
    pane.add(right_frame, width=380)

    # Editor Layout
    tk.Label(right_frame, text="Base String Offset:", fg=fg_color, bg=bg_color).grid(
        row=0, column=0, sticky="w", pady=5
    )
    tk.Label(
        right_frame,
        textvariable=selected_base_offset,
        fg="#e0a96d",
        bg=bg_color,
        font=("Arial", 10, "bold"),
    ).grid(row=0, column=1, sticky="w", pady=5)

    tk.Label(
        right_frame, text="Relative Shift (Bytes):", fg=fg_color, bg=bg_color
    ).grid(row=1, column=0, sticky="w", pady=5)
    rel_entry = tk.Entry(
        right_frame,
        textvariable=rel_var,
        width=10,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    )
    rel_entry.grid(row=1, column=1, sticky="w", pady=5)

    quick_frame = tk.Frame(right_frame, bg=bg_color)
    quick_frame.grid(row=2, column=1, columnspan=2, sticky="w")

    def set_rel(val):
        rel_var.set(str(val))
        update_target_offset()

    tk.Button(
        quick_frame,
        text="-32",
        width=4,
        command=lambda: set_rel(-32),
        fg=fg_color,
        bg=btn_color,
    ).pack(side="left", padx=2)
    tk.Button(
        quick_frame,
        text="-24",
        width=4,
        command=lambda: set_rel(-24),
        fg=fg_color,
        bg=btn_color,
    ).pack(side="left", padx=2)
    tk.Button(
        quick_frame,
        text="-16",
        width=4,
        command=lambda: set_rel(-16),
        fg=fg_color,
        bg=btn_color,
    ).pack(side="left", padx=2)
    tk.Button(
        quick_frame,
        text=" 0 ",
        width=4,
        command=lambda: set_rel(0),
        fg=fg_color,
        bg=btn_color,
    ).pack(side="left", padx=2)

    tk.Label(
        right_frame, text="Target Offset (Dec/Hex):", fg=fg_color, bg=bg_color
    ).grid(row=3, column=0, sticky="w", pady=8)
    target_entry = tk.Entry(
        right_frame,
        textvariable=target_var,
        width=15,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    )
    target_entry.grid(row=3, column=1, sticky="w", pady=8)

    tk.Label(right_frame, text="Data Type:", fg=fg_color, bg=bg_color).grid(
        row=4, column=0, sticky="w", pady=5
    )
    dtype_cb = ttk.Combobox(
        right_frame,
        textvariable=dtype_var,
        values=[
            "Byte (uint8)",
            "Int16 (short)",
            "Int32 (int)",
            "Float32",
            "String (ANSI)",
        ],
        state="readonly",
        width=15,
    )
    dtype_cb.grid(row=4, column=1, sticky="w", pady=5)

    tk.Label(right_frame, text="Current Value:", fg=fg_color, bg=bg_color).grid(
        row=5, column=0, sticky="w", pady=8
    )
    current_val_entry = tk.Entry(
        right_frame,
        textvariable=current_val_var,
        state="readonly",
        width=25,
        fg="#00ff00",
        font=("Consolas", 10, "bold"),
    )
    current_val_entry.grid(row=5, column=1, columnspan=2, sticky="w", pady=8)

    tk.Label(right_frame, text="New Value to Write:", fg=fg_color, bg=bg_color).grid(
        row=6, column=0, sticky="w", pady=5
    )
    new_val_entry = tk.Entry(
        right_frame,
        textvariable=new_val_var,
        width=25,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    )
    new_val_entry.grid(row=6, column=1, columnspan=2, sticky="w", pady=5)

    scanned_results = []
    selected_base_dec = None

    def read_current_value(*args):
        path = dat_var.get()
        if not path or not os.path.exists(path):
            current_val_var.set("No File Selected")
            return

        try:
            addr_str = target_var.get().strip()
            if not addr_str:
                return

            if addr_str.lower().startswith("0x"):
                addr = int(addr_str, 16)
            else:
                addr = int(addr_str)

            dtype = dtype_var.get()

            with open(path, "rb") as f:
                f.seek(0, 2)
                fsize = f.tell()
                if addr < 0 or addr >= fsize:
                    current_val_var.set("N/A (Out of Bounds)")
                    return
                f.seek(addr)
                chunk = f.read(128)

            if not chunk:
                current_val_var.set("N/A (EOF)")
                return

            if dtype == "Byte (uint8)":
                current_val_var.set(str(chunk[0]))
            elif dtype == "Int16 (short)":
                if len(chunk) < 2:
                    current_val_var.set("N/A (Insufficient Bytes)")
                    return
                val = struct.unpack_from("<h", chunk, 0)[0]
                current_val_var.set(str(val))
            elif dtype == "Int32 (int)":
                if len(chunk) < 4:
                    current_val_var.set("N/A (Insufficient Bytes)")
                    return
                val = struct.unpack_from("<i", chunk, 0)[0]
                current_val_var.set(str(val))
            elif dtype == "Float32":
                if len(chunk) < 4:
                    current_val_var.set("N/A (Insufficient Bytes)")
                    return
                val = struct.unpack_from("<f", chunk, 0)[0]
                current_val_var.set(f"{val:.6f}")
            elif dtype == "String (ANSI)":
                chars = []
                for b in chunk:
                    if b == 0:
                        break
                    chars.append(chr(b))
                current_val_var.set("".join(chars))
        except Exception as e:
            current_val_var.set(f"Error: {e}")

    def update_target_offset(*args):
        nonlocal selected_base_dec
        if selected_base_dec is None:
            return
        try:
            rel_str = rel_var.get().strip()
            if not rel_str:
                rel_val = 0
            elif rel_str == "-":
                return
            else:
                rel_val = int(rel_str)

            target = selected_base_dec + rel_val
            target_var.set(str(target))
        except ValueError:
            pass

    def perform_write():
        path = dat_var.get()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Please select a valid .dat chunk first!")
            return

        try:
            addr_str = target_var.get().strip()
            if addr_str.lower().startswith("0x"):
                addr = int(addr_str, 16)
            else:
                addr = int(addr_str)

            dtype = dtype_var.get()
            new_val_str = new_val_var.get().strip()

            if dtype == "Byte (uint8)":
                val = int(new_val_str)
                packed = struct.pack("<B", val)
            elif dtype == "Int16 (short)":
                val = int(new_val_str)
                packed = struct.pack("<h", val)
            elif dtype == "Int32 (int)":
                val = int(new_val_str)
                packed = struct.pack("<i", val)
            elif dtype == "Float32":
                val = float(new_val_str)
                packed = struct.pack("<f", val)
            elif dtype == "String (ANSI)":
                packed = new_val_str.encode("cp1252", errors="ignore")
            else:
                return

            with open(path, "r+b") as f:
                f.seek(0, 2)
                fsize = f.tell()
                if addr < 0 or addr + len(packed) > fsize:
                    messagebox.showerror(
                        "Error", "Target offset is out of file bounds!"
                    )
                    return
                f.seek(addr)
                f.write(packed)

            print(f"[+] Modified {dtype} at offset {addr} -> '{new_val_str}'")
            read_current_value()

            if dtype == "String (ANSI)":
                trigger_scan()

            messagebox.showinfo(
                "Success", f"Successfully wrote '{new_val_str}' at offset {addr}!"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write value: {e}")

    tk.Button(
        right_frame,
        text="Write value to DAT File",
        command=perform_write,
        fg=fg_color,
        bg="#5f1e1e",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=5,
        activebackground="#7f2e2e",
    ).grid(row=7, column=0, columnspan=2, pady=15)

    def trigger_scan():
        nonlocal scanned_results
        path = dat_var.get()
        if not path or not os.path.exists(path):
            return

        scanned_results = scan_printable_strings(path)
        update_tree()

    def update_tree(*args):
        for item in tree.get_children():
            tree.delete(item)

        filter_text = search_var.get().lower()

        for offset, val in scanned_results:
            if filter_text and filter_text not in val.lower():
                continue
            tree.insert("", tk.END, values=(offset, f"0x{offset:04X}", val))

    def on_tree_select(event):
        nonlocal selected_base_dec
        selected = tree.selection()
        if not selected:
            return
        item = tree.item(selected[0])
        dec_offset = int(item["values"][0])
        selected_base_dec = dec_offset

        selected_base_offset.set(f"0x{dec_offset:04X} ({dec_offset})")
        rel_var.set("0")
        update_target_offset()

    tree.bind("<<TreeviewSelect>>", on_tree_select)
    rel_var.trace_add("write", update_target_offset)
    target_var.trace_add("write", read_current_value)
    dtype_var.trace_add("write", read_current_value)
    search_var.trace_add("write", update_tree)

    def on_closing():
        sys.stdout = orig_stdout
        sys.stderr = orig_stderr
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        launch_gui()
    else:
        cmd = sys.argv[1]
        if cmd == "export_all":
            if len(sys.argv) < 4:
                print("Usage: python sf_pak_cff.py export_all english.cff work_folder")
            else:
                unpack_all(sys.argv[2], sys.argv[3])
        elif cmd == "pack_all":
            if len(sys.argv) < 4:
                print(
                    "Usage: python sf_pak_cff.py pack_all work_folder russian.cff [compression_level]"
                )
            else:
                level = 6
                if len(sys.argv) >= 5:
                    try:
                        level = int(sys.argv[4])
                    except ValueError:
                        pass
                pack_all(sys.argv[2], sys.argv[3], level)
        elif cmd == "pack_pak":
            if len(sys.argv) < 4:
                print(
                    "Usage: python sf_pak_cff.py pack_pak source_folder out_archive.pak [sf1/sf2] [scratch/meta]"
                )
            else:
                src = sys.argv[2]
                out = sys.argv[3]
                fmt = "sf2"
                if len(sys.argv) >= 5:
                    fmt = sys.argv[4].lower()

                mode = "meta"
                if len(sys.argv) >= 6:
                    mode = sys.argv[5].lower()

                if fmt == "sf1":
                    if mode == "scratch":
                        pack_pak_sf1_from_scratch(src, out, print)
                    else:
                        pack_pak_sf1(src, out, print)
                else:
                    pack_pak_sf2(src, out, 6, print)
        elif len(sys.argv) >= 4:
            p1 = sys.argv[2]
            p2 = sys.argv[3]
            if cmd == "unpack":
                unpack_cff(p1, p2)
            elif cmd == "pack":
                level = 6
                if len(sys.argv) >= 5:
                    try:
                        level = int(sys.argv[4])
                    except ValueError:
                        pass
                pack_cff(p1, p2, level)
            elif cmd == "export":
                export_text(p1, p2)
            elif cmd == "import":
                import_text(p1, p2)
        else:
            print("Invalid CLI call.")
