import struct
import os


def parse_meta_v2(filepath):
    if not os.path.exists(filepath):
        print(f"[!] File {filepath} not found! Place it in the same directory.")
        return

    with open(filepath, "rb") as f:
        meta_bytes = f.read()

    num_files = struct.unpack_from("<I", meta_bytes, 76)[0]
    root_idx = struct.unpack_from("<I", meta_bytes, 80)[0]
    data_start = struct.unpack_from("<I", meta_bytes, 84)[0]
    name_list_start = 92 + num_files * 16

    print("Header Info:")
    print(f"  Num Files: {num_files}")
    print(f"  Root Index: {root_idx}")
    print(f"  Data Start: {data_start}")

    print("\nDetailed file table dump (first 10 files):")
    for i in range(10):
        offset_in_meta = 92 + i * 16
        size, offset, name_off_raw, dir_off_raw = struct.unpack_from(
            "<IIII", meta_bytes, offset_in_meta
        )

        name_off = name_off_raw & 0x00FFFFFF
        dir_off = dir_off_raw & 0x00FFFFFF

        # Read 2-byte prefix from the string table
        prefix_pos = name_list_start + name_off
        prefix_bytes = meta_bytes[prefix_pos : prefix_pos + 2]
        prefix_hex = prefix_bytes.hex()

        # Read file name (reversed null-terminated string)
        pos = name_list_start + name_off + 2
        chars = []
        while pos < len(meta_bytes) and meta_bytes[pos] != 0:
            chars.append(meta_bytes[pos])
            pos += 1
        chars.reverse()
        file_name = bytes(chars).decode("latin1", errors="ignore")

        # Read directory name (reversed null-terminated string)
        dir_name = ""
        if dir_off != 0x00FFFFFF:
            pos = name_list_start + dir_off
            d_chars = []
            while pos < len(meta_bytes) and meta_bytes[pos] != 0:
                d_chars.append(meta_bytes[pos])
                pos += 1
            d_chars.reverse()
            dir_name = bytes(d_chars).decode("latin1", errors="ignore")

        print(f"File {i:4d}:")
        print(f"  Name: '{dir_name}\\{file_name}'")
        print(f"  Size: {size}, Offset: {offset}")
        print(
            f"  name_off_raw: {hex(name_off_raw)} (offset={name_off}, high_byte={hex(name_off_raw >> 24)})"
        )
        print(
            f"  dir_off_raw : {hex(dir_off_raw)} (offset={dir_off}, high_byte={hex(dir_off_raw >> 24)})"
        )
        print(f"  String Table Prefix: {prefix_hex} (bytes: {list(prefix_bytes)})")


parse_meta_v2(".sf1_meta.bin")
