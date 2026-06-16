"""
SpellForce 1 & 2 - Complete Modding & Localization Suite
Supports CFF Containers, DAT Database Chunks, Binary Scanning/Editing, and Batch PAK Archives.
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
# 1. CFF CONTAINER PACK / UNPACK ENGINE (SpellForce 2 Database Containers)
# ==============================================================================


def unpack_cff(input_file, out_dir):
    """Unpacks a .cff archive container into separate .dat chunks."""
    print(f"[*] Unpacking CFF: {input_file} -> {out_dir}")
    os.makedirs(out_dir, exist_ok=True)

    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return False

    if data[0:4] != b"\x12\xdd\x72\xdd":
        print("[!] Error: Invalid CFF signature!")
        return False

    with open(os.path.join(out_dir, "header.bin"), "wb") as f:
        f.write(data[0:20])

    manifest = {"chunks": []}
    offset = 20
    chunk_idx = 0

    while offset < len(data):
        c_id, flag1, comp_size, flag2, uncomp_size = struct.unpack_from(
            "<IHIHI", data, offset
        )
        offset += 16
        comp_data = data[offset : offset + comp_size]
        offset += comp_size

        try:
            uncomp_data = zlib.decompress(comp_data)
            chunk_name = f"chunk_{chunk_idx}.dat"

            with open(os.path.join(out_dir, chunk_name), "wb") as f:
                f.write(uncomp_data)

            manifest["chunks"].append(
                {
                    "file": chunk_name,
                    "id": c_id,
                    "flag1": flag1,
                    "flag2": flag2,
                }
            )
        except Exception as e:
            print(f"[!] Error decompressing chunk {chunk_idx}: {e}")

        chunk_idx += 1

    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=4)

    print("[+] Container unpacking completed!")
    return True


def pack_cff(input_dir, out_file, comp_level=6):
    """Packs raw .dat chunks back into a unified .cff container."""
    print(
        f"[*] Packing CFF (compression level: {comp_level}): {input_dir} -> {out_file}"
    )
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

    with open(out_file, "wb") as out:
        with open(os.path.join(input_dir, "header.bin"), "rb") as hf:
            out.write(hf.read())

        for chunk in manifest["chunks"]:
            with open(os.path.join(input_dir, chunk["file"]), "rb") as cf:
                uncomp_data = cf.read()

            comp_data = zlib.compress(uncomp_data, level=comp_level)
            out.write(
                struct.pack(
                    "<IHIHI",
                    chunk["id"],
                    chunk["flag1"],
                    len(comp_data),
                    chunk["flag2"],
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
    """Detects CFF format schemas (Format A, B, C or pure binary)."""
    if len(data) < 8:
        return "binary", 0, 0

    count = struct.unpack_from("<I", data, 0)[0]
    if count == 0 or count > 200000:
        return "binary", 0, 0

    # 1. Format C (developer_table) - single-byte Windows-1252 / ANSI
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

    # 2. Format A (string_table) - UTF-16 LE
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

    # 3. Format B (table_based) - multi-string UTF-16 LE
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

    count = struct.unpack_from("<I", data, 0)[0]
    offset = 4

    fmt, num_strings, extra_bytes = detect_format(data)
    if fmt == "binary":
        return False

    print(
        f"[*] Exporting text: {os.path.basename(chunk_path)} -> {os.path.basename(json_path)} | format: {fmt}"
    )

    texts = {}
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
            name = data[offset : offset + name_len].decode("cp1252", errors="ignore")
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

    is_table_based = False
    is_developer_table = False
    num_strings = 0

    first_key = next(iter(texts.keys()), None)
    if first_key is not None and "_" in first_key:
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

    with open(chunk_path, "wb") as f:
        if not is_table_based and not is_developer_table:
            # Rebuild Format A (string_table)
            f.write(struct.pack("<I", len(texts)))
            for key, text in texts.items():
                f.write(b"\x01")  # Flag

                kb = key.encode("utf-8")
                f.write(struct.pack("<I", len(kb)))
                f.write(kb)

                tb = text.encode("utf-16-le")
                f.write(struct.pack("<I", len(tb) // 2))
                f.write(tb)

        elif is_developer_table:
            # Rebuild Format C (developer_table)
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
                name_bytes = entry["name"].encode("cp1252", errors="ignore")
                f.write(struct.pack("<I", len(name_bytes)))
                f.write(name_bytes)
                key_bytes = entry["key"].encode("cp1252", errors="ignore")
                f.write(struct.pack("<I", len(key_bytes)))
                f.write(key_bytes)
        else:
            # Rebuild Format B (table_based)
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

            import_text(json_path, chunk_path)

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


def read_pak_entries(pak_path):
    """Reads the file index from either a SpellForce 1 or SpellForce 2 .pak archive."""
    if not os.path.exists(pak_path):
        raise FileNotFoundError(f"File not found: {pak_path}")

    with open(pak_path, "rb") as fs:
        # Check if it's a SpellForce 1 PAK
        fs.seek(0, 2)
        total_len = fs.tell()
        if total_len >= 28:
            fs.seek(0)
            first_int = struct.unpack("<I", fs.read(4))[0]
            if first_int == 4:
                magic_bytes = fs.read(24)
                if magic_bytes.startswith(b"MASSIVE PAKFILE"):
                    return "sf1", read_sf1_entries(fs, total_len)

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


def read_sf1_entries(fs, total_len):
    """Helper method to parse the legacy SpellForce 1 directory block."""
    fs.seek(76)
    num_files, root_idx, data_start, archive_size = struct.unpack("<IIII", fs.read(16))

    fs.seek(92)
    file_entries = []
    for _ in range(num_files):
        size, offset, name_off, dir_off = struct.unpack("<IIII", fs.read(16))
        file_entries.append(
            {
                "size": size,
                "offset": offset,
                "name_off": name_off & 0x00FFFFFF,
                "dir_off": dir_off & 0x00FFFFFF,
            }
        )

    name_list_start = fs.tell()
    entries = []

    for entry in file_entries:
        file_name = read_reversed_string_sf1(fs, entry["name_off"] + 2, name_list_start)
        dir_name = ""
        if entry["dir_off"] != 0x00FFFFFF and entry["dir_off"] != 0xFFFFFF:
            dir_name = read_reversed_string_sf1(fs, entry["dir_off"], name_list_start)

        full_path = file_name if not dir_name else dir_name + "\\" + file_name
        full_path = full_path.replace("/", "\\")

        entries.append(
            {
                "name": full_path,
                "offset": data_start + entry["offset"],
                "size": int(entry["size"]),
            }
        )

    return entries


def unpack_pak(pak_path, out_dir, progress_callback=None):
    """Unpacks all files from a SpellForce 1 or 2 .pak archive to the specified directory."""
    fmt, entries = read_pak_entries(pak_path)
    os.makedirs(out_dir, exist_ok=True)

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
    """Assembles files into a legacy SpellForce 1 format .pak archive."""
    files = []
    for root, _, filenames in os.walk(source_dir):
        for filename in filenames:
            files.append(os.path.join(root, filename))

    with open(out_pak_path, "wb") as fs:
        fs.write(b"\x00" * 92)

        entries = []
        name_list_buf = bytearray(b"\x00\x00")
        dir_offsets = {}

        def write_reversed_string(s):
            offset = len(name_list_buf)
            b_str = s.encode("latin1", errors="ignore")
            reversed_b = bytearray(b_str)
            reversed_b.reverse()
            name_list_buf.extend(reversed_b)
            name_list_buf.append(0)
            return offset

        for idx, file_path in enumerate(files):
            rel_path = (
                os.path.relpath(file_path, source_dir)
                .replace("/", "\\")
                .replace(os.sep, "\\")
                .lower()
            )
            dir_name = os.path.dirname(rel_path)
            file_name = os.path.basename(rel_path)

            if progress_callback:
                progress_callback(f"Packing SF1 ({idx + 1}/{len(files)}): {rel_path}")

            dir_offset = 0
            if dir_name:
                if dir_name not in dir_offsets:
                    dir_offsets[dir_name] = write_reversed_string(dir_name)
                dir_offset = dir_offsets[dir_name]

            name_offset = write_reversed_string(file_name) - 2

            entries.append(
                {
                    "size": 0,
                    "offset": 0,
                    "name_off": name_offset,
                    "dir_off": dir_offset,
                    "fullpath": file_path,
                }
            )

        for _ in entries:
            fs.write(struct.pack("<IIII", 0, 0, 0, 0))

        fs.write(name_list_buf)

        data_start_offset = fs.tell()

        for idx, entry in enumerate(entries):
            file_offset = fs.tell() - data_start_offset
            with open(entry["fullpath"], "rb") as in_f:
                shutil.copyfileobj(in_f, fs)

            entry["offset"] = file_offset
            entry["size"] = fs.tell() - data_start_offset - file_offset
            entries[idx] = entry

        archive_size = fs.tell()

        fs.seek(92)
        for entry in entries:
            fs.write(
                struct.pack(
                    "<IIII",
                    entry["size"],
                    entry["offset"],
                    entry["name_off"],
                    entry["dir_off"],
                )
            )

        fs.seek(0)
        fs.write(struct.pack("<I", 4))

        magic_bytes = b"MASSIVE PAKFILE V 4.0\r\n"
        magic_padded = magic_bytes.ljust(24, b"\x00")
        fs.write(magic_padded)

        fs.write(b"\x00" * 44)
        fs.write(struct.pack("<IIII", 0, len(entries), 0, data_start_offset))
        fs.write(struct.pack("<I", archive_size))

    if progress_callback:
        progress_callback("Pack complete!")


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


def batch_pack_folders(root_dir, fmt, comp_level=6, progress_callback=None):
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
            base_name = folder_name[:-10]  # Remove "_extracted"

        out_pak_path = os.path.join(root_dir, base_name + ".pak")

        if progress_callback:
            progress_callback(
                f"[*] Packing folder: {folder_name} -> {os.path.basename(out_pak_path)}"
            )
        try:
            if fmt == "sf1":
                pack_pak_sf1(subdir, out_pak_path, progress_callback)
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
    root.geometry("1020x680")
    root.configure(bg="#1E1E1E")

    # Styling
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

    # Initialize visual frames
    tab_archive = tk.Frame(notebook, bg=bg_color)
    tab_inspector = tk.Frame(notebook, bg=bg_color)
    tab_log = tk.Frame(notebook, bg=bg_color)

    # Add tabs to notebook - Archive Tool is FIRST, Progress Terminal is LAST
    notebook.add(tab_archive, text=" Archive Tool ")
    notebook.add(tab_inspector, text=" Binary Chunk Inspector ")
    notebook.add(tab_log, text=" Progress Terminal ")

    # ================= TAB 3: PROGRESS TERMINAL (tab_log) =================
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

    # 100% Thread-Safe GUI Logging Mechanism
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

    # Redirect streams safely (keeps physical console prints working simultaneously)
    orig_stdout = sys.stdout
    orig_stderr = sys.stderr
    sys.stdout = ThreadSafeLogger(log_queue, orig_stdout)
    sys.stderr = ThreadSafeLogger(log_queue, orig_stderr)

    # Poll start
    root.after(100, poll_log_queue)

    def run_thread(target):
        threading.Thread(target=target, daemon=True).start()

    # ================= TAB 1: ARCHIVE TOOL (tab_archive) =================
    # Variables for CFF and PAK
    cff_var = tk.StringVar(value="")
    work_dir_var = tk.StringVar(value="work_folder")
    comp_level_var = tk.IntVar(value=6)
    pak_file_var = tk.StringVar(value="")
    pak_out_var = tk.StringVar(value="extracted_pak")
    pak_src_var = tk.StringVar(value="")
    pak_fmt_var = tk.StringVar(value="SpellForce 2 (.pak)")
    pak_comp_var = tk.IntVar(value=6)
    status_msg_var = tk.StringVar(value="Ready.")

    # Main Split layout on Tab 1
    pane_archive = tk.PanedWindow(tab_archive, orient="horizontal", bg=bg_color, bd=0)
    pane_archive.pack(fill="both", expand=True, padx=20, pady=5)

    # Left Column: Configuration Frames (stacked vertically)
    left_control_col = tk.Frame(pane_archive, bg=bg_color)
    pane_archive.add(left_control_col, width=350)

    # Unpack Frame (PAK)
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
                fmt, entries = read_pak_entries(path)
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

    def on_fmt_change(event):
        if pak_fmt_cb.get() == "SpellForce 1 (.pak)":
            pak_scale.config(state="disabled", fg="#555555")
        else:
            pak_scale.config(state="normal", fg=fg_color)

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

    def on_pack_pak():
        src_dir = pak_src_var.get().strip()
        fmt_name = pak_fmt_var.get()
        level = pak_comp_var.get()

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

        if fmt_name == "SpellForce 1 (.pak)":
            run_thread(lambda: pack_pak_sf1(src_dir, out_file, print))
        else:
            run_thread(lambda: pack_pak_sf2(src_dir, out_file, level, print))

    def gui_batch_pack_pak():
        root_dir = filedialog.askdirectory(
            title="Select Root Folder containing subfolders to pack"
        )
        if not root_dir:
            return

        fmt_name = pak_fmt_var.get()
        level = pak_comp_var.get()
        fmt = "sf1" if fmt_name == "SpellForce 1 (.pak)" else "sf2"

        text_log.delete("1.0", tk.END)
        notebook.select(tab_log)
        run_thread(lambda: batch_pack_folders(root_dir, fmt, level, print))

    tk.Button(
        pack_frame,
        text="Pack Folder",
        command=on_pack_pak,
        fg=fg_color,
        bg="#5f1e1e",
        font=("Arial", 10, "bold"),
        padx=5,
        pady=3,
    ).grid(row=3, column=1, sticky="w", pady=10)

    tk.Button(
        pack_frame,
        text="Batch Pack...",
        command=gui_batch_pack_pak,
        fg=fg_color,
        bg="#5f1e1e",
        font=("Arial", 10, "bold"),
        padx=5,
        pady=3,
    ).grid(row=3, column=2, sticky="w", pady=10, padx=5)

    # ---- CFF Container Tool (Stacked below PAK frames) ----
    cff_frame = tk.LabelFrame(
        left_control_col,
        text=" SpellForce 2 CFF Database Containers ",
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

    # CFF execution buttons aligned neatly inside left frame
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

    # Right Column: Expandable TreeView (Archive Content Explorer)
    right_tree_col = tk.LabelFrame(
        pane_archive,
        text=" Archive Content Explorer ",
        font=("Arial", 10, "bold"),
        fg=fg_color,
        bg=bg_color,
        padx=10,
        pady=10,
    )
    pane_archive.add(right_tree_col, width=590)

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
        show="tree",  # Hide table headers, strictly display directory tree
        yscrollcommand=tree_scroll.set,
        style="Archive.Treeview",
    )
    archive_tree.pack(fill="both", expand=True, side="left")
    tree_scroll.config(command=archive_tree.yview)

    # Dynamic TreeView Generators
    def populate_tree_from_entries(tree_widget, entries, archive_name):
        for item in tree_widget.get_children():
            tree_widget.delete(item)

        root_id = tree_widget.insert("", "end", text=archive_name, open=True)
        nodes = {"": root_id}

        for entry in entries:
            path = entry["name"]
            parts = re.split(r"[\\/]", path)

            current_path = ""
            parent_id = root_id

            for idx, part in enumerate(parts):
                new_path = part if not current_path else current_path + "\\" + part

                if new_path not in nodes:
                    node_id = tree_widget.insert(
                        parent_id, "end", text=part, open=False
                    )
                    nodes[new_path] = node_id

                parent_id = nodes[new_path]
                current_path = new_path

    def populate_tree_from_directory(tree_widget, dir_path):
        for item in tree_widget.get_children():
            tree_widget.delete(item)

        root_name = os.path.basename(dir_path) or "Folder"
        root_id = tree_widget.insert("", "end", text=root_name, open=True)

        def recurse(parent_node, current_dir):
            try:
                # Add subfolders recursively
                for d in sorted(os.listdir(current_dir)):
                    full_path = os.path.join(current_dir, d)
                    if os.path.isdir(full_path):
                        node_id = tree_widget.insert(
                            parent_node, "end", text=d, open=False
                        )
                        recurse(node_id, full_path)

                # Add files
                for f in sorted(os.listdir(current_dir)):
                    full_path = os.path.join(current_dir, f)
                    if os.path.isfile(full_path):
                        tree_widget.insert(parent_node, "end", text=f, open=False)
            except Exception as e:
                print(f"[!] Error scanning directory: {e}")

        recurse(root_id, dir_path)

    # Status Bar Frame at the bottom of the first tab (tab_archive)
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

    # ================= TAB 2: BINARY CHUNK INSPECTOR (tab_inspector) =================
    # Variables for Tab 2 (Inspector)
    dat_var = tk.StringVar(value="")
    search_var = tk.StringVar(value="")
    selected_base_offset = tk.StringVar(value="N/A")
    rel_var = tk.StringVar(value="0")
    target_var = tk.StringVar(value="0")
    dtype_var = tk.StringVar(value="Int16 (short)")
    current_val_var = tk.StringVar(value="No File")
    new_val_var = tk.StringVar(value="")

    # Layout: PanedWindow (Split screen into Left (List) and Right (Editor))
    pane = tk.PanedWindow(tab_inspector, orient="horizontal", bg=bg_color, bd=0)
    pane.pack(fill="both", expand=True, padx=20, pady=5)

    # Left Frame (Scanner List)
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

    # Treeview list of strings
    tree_frame = tk.Frame(left_frame, bg="#121212")
    tree_frame.pack(fill="both", expand=True, pady=5)

    scrollbar = tk.Scrollbar(tree_frame, orient="vertical")
    scrollbar.pack(side="right", fill="y")

    # Treeview configuration
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

    # Quick helper shift buttons
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

    # Core logic functions for Binary Editor
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

    # Write Button Layout
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

        # Load and scan the file
        scanned_results = scan_printable_strings(path)
        update_tree()

    def update_tree(*args):
        # Clear old rows
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

    # Event Bindings for Right Editor Pane
    tree.bind("<<TreeviewSelect>>", on_tree_select)
    rel_var.trace_add("write", update_target_offset)
    target_var.trace_add("write", read_current_value)
    dtype_var.trace_add("write", read_current_value)
    search_var.trace_add("write", update_tree)

    # Safe closing: restore streams
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
                print(
                    "Usage: python sf2_cff_loc_tool.py export_all english.cff work_folder"
                )
            else:
                unpack_all(sys.argv[2], sys.argv[3])
        elif cmd == "pack_all":
            if len(sys.argv) < 4:
                print(
                    "Usage: python sf2_cff_loc_tool.py pack_all work_folder russian.cff [compression_level]"
                )
            else:
                level = 6
                if len(sys.argv) >= 5:
                    try:
                        level = int(sys.argv[4])
                    except ValueError:
                        pass
                pack_all(sys.argv[2], sys.argv[3], level)
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
