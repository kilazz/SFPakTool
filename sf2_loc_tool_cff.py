import json
import os
import re
import struct
import sys
import zlib


def unpack_cff(input_file, out_dir):
    print(f"[*] Unpacking CFF: {input_file} -> {out_dir}")
    os.makedirs(out_dir, exist_ok=True)

    with open(input_file, "rb") as f:
        data = f.read()

    if data[0:4] != b"\x12\xdd\x72\xdd":
        print("[!] Error: Invalid CFF signature!")
        return

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
            print(f"[!] Error in chunk {chunk_idx}: {e}")

        chunk_idx += 1

    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=4)

    print("[+] Unpacking completed!")


def pack_cff(input_dir, out_file, comp_level=6):
    print(
        f"[*] Packing CFF (compression level: {comp_level}): {input_dir} -> {out_file}"
    )
    manifest_path = os.path.join(input_dir, "manifest.json")

    if not os.path.exists(manifest_path):
        print("[!] Error: manifest.json not found!")
        return

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

    print("[+] Packing completed!")


def detect_format(data):
    """Detects binary chunk format and its structure."""
    if len(data) < 8:
        return "string_table", 0, 0

    count = struct.unpack_from("<I", data, 0)[0]
    if count == 0:
        return "string_table", 0, 0

    try:
        offset = 4
        # Try string_table (Format A)
        offset += 1  # Skip flag
        key_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4 + key_len
        if offset + 4 > len(data):
            raise Exception()
        text_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4 + text_len * 2

        if offset == len(data) or (count == 1 and offset <= len(data)):
            return "string_table", 0, 0
    except Exception:
        pass

    # Try table_based (Format B) with N strings and E padding bytes (0-16 bytes)
    for E in range(17):
        for N in range(1, 6):
            offset = 4
            success = True
            for _ in range(count):
                if offset + 4 + E > len(data):
                    success = False
                    break
                offset += 4 + E  # ID + padding
                for _ in range(N):
                    if offset + 4 > len(data):
                        success = False
                        break
                    str_len = struct.unpack_from("<I", data, offset)[0]
                    offset += 4 + str_len * 2

            if success and offset == len(data):
                return "table_based", N, E

    return "string_table", 0, 0


def export_text(chunk_path, json_path):
    print(f"[*] Exporting text: {chunk_path} -> {json_path}")
    with open(chunk_path, "rb") as f:
        data = f.read()

    if len(data) < 4:
        print("[!] Error: File is too small!")
        return

    count = struct.unpack_from("<I", data, 0)[0]
    offset = 4

    fmt, num_strings, extra_bytes = detect_format(data)
    print(
        f"[*] Auto-detecting format: {fmt} (entries: {count}, strings per entry: {num_strings}, padding: {extra_bytes})"
    )

    texts = {}
    if fmt == "string_table":
        for _ in range(count):
            if offset >= len(data):
                break

            offset += 1  # Skip hidden flag byte (0x01)

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
    else:  # table_based
        for i in range(count):
            if offset >= len(data):
                break

            id_val = struct.unpack_from("<I", data, offset)[0]
            offset += 4

            # Read technical padding
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

                # Key format: "index_ID_parametersHEX_stringNumber"
                texts[f"{i}_{id_val}_{extra_hex}_str{s}"] = text

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(texts, f, indent=4, ensure_ascii=False)

    print(f"[+] Exported {len(texts)} entries!")


def import_text(json_path, chunk_path):
    print(f"[*] Importing text: {json_path} -> {chunk_path}")
    with open(json_path, "r", encoding="utf-8") as f:
        texts = json.load(f)

    # Check format using JSON keys
    is_table_based = False
    num_strings = 0
    first_key = next(iter(texts.keys()), None)
    if first_key is not None and "_" in first_key:
        parts = first_key.split("_", 3)
        if (
            len(parts) == 4
            and parts[0].isdigit()
            and parts[1].isdigit()
            and parts[3].startswith("str")
        ):
            is_table_based = True
            max_str_idx = 0
            for key in texts.keys():
                k_parts = key.split("_", 3)
                if len(k_parts) == 4 and k_parts[3].startswith("str"):
                    str_idx = int(k_parts[3][3:])
                    if str_idx > max_str_idx:
                        max_str_idx = str_idx
            num_strings = max_str_idx + 1

    with open(chunk_path, "wb") as f:
        if not is_table_based:
            # Import as string_table
            f.write(struct.pack("<I", len(texts)))
            for key, text in texts.items():
                f.write(b"\x01")  # Hidden flag

                kb = key.encode("utf-8")
                f.write(struct.pack("<I", len(kb)))
                f.write(kb)

                tb = text.encode("utf-16-le")
                f.write(struct.pack("<I", len(tb) // 2))
                f.write(tb)
        else:
            # Import as table_based
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

    print("[+] Text successfully written to binary chunk!")


def unpack_all(cff_path, work_dir):
    """Batch export: unpacks CFF and exports all non-empty texts."""
    print(f"[*] Starting full unpack cycle: {cff_path} -> {work_dir}")
    unpack_cff(cff_path, work_dir)

    json_dir = os.path.join(work_dir, "texts_json")
    os.makedirs(json_dir, exist_ok=True)

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
                continue

            fmt, num_strings, extra_bytes = detect_format(data)

            # Skip empty chunks
            if fmt == "string_table" and struct.unpack_from("<I", data, 0)[0] == 0:
                continue

            desc_name = f"chunk_{chunk_idx}_strings.json"
            json_path = os.path.join(json_dir, desc_name)

            export_text(chunk_path, json_path)

    print("[+] All text chunks exported to texts_json directory!")


def pack_all(work_dir, cff_path, comp_level=6):
    """Batch import: imports all JSONs back into .dat files and packs the CFF."""
    print(
        f"[*] Starting full pack cycle (compression: {comp_level}): {work_dir} -> {cff_path}"
    )
    json_dir = os.path.join(work_dir, "texts_json")

    if not os.path.exists(json_dir):
        print("[!] Error: Directory texts_json not found!")
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
    print("[+] Localized CFF archive successfully packed!")


def launch_gui():
    """Launches the graphical user interface."""
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.title("SpellForce 2 CFF Localization Tool")
    root.geometry("700x560")
    root.configure(bg="#212121")

    # Dark theme styles
    fg_color = "#ffffff"
    bg_color = "#212121"
    btn_color = "#333333"
    entry_color = "#2d2d2d"

    class GuiLogger:
        def __init__(self, text_widget):
            self.text_widget = text_widget

        def write(self, message):
            self.text_widget.insert(tk.END, message)
            self.text_widget.see(tk.END)

        def flush(self):
            pass

    cff_var = tk.StringVar(value="")
    work_dir_var = tk.StringVar(value="work_folder")
    comp_level_var = tk.IntVar(value=6)

    tk.Label(
        root,
        text="SpellForce 2 - CFF Localization Tool",
        font=("Arial", 16, "bold"),
        fg="#e0a96d",
        bg=bg_color,
    ).pack(pady=10)

    # Path Settings
    file_frame = tk.LabelFrame(
        root,
        text=" Path & Compression Settings ",
        font=("Arial", 10, "bold"),
        fg=fg_color,
        bg=bg_color,
        padx=10,
        pady=10,
    )
    file_frame.pack(fill="x", padx=20, pady=5)

    tk.Label(file_frame, text="Localization .cff file:", fg=fg_color, bg=bg_color).grid(
        row=0, column=0, sticky="w"
    )
    tk.Entry(
        file_frame,
        textvariable=cff_var,
        width=50,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    ).grid(row=0, column=1, padx=5)

    def select_cff():
        path = filedialog.askopenfilename(filetypes=[("CFF files", "*.cff")])
        if path:
            cff_var.set(path)

    tk.Button(
        file_frame,
        text="Browse...",
        command=select_cff,
        fg=fg_color,
        bg=btn_color,
        activebackground="#555555",
    ).grid(row=0, column=2)

    tk.Label(
        file_frame, text="Working directory (work_folder):", fg=fg_color, bg=bg_color
    ).grid(row=1, column=0, sticky="w", pady=5)
    tk.Entry(
        file_frame,
        textvariable=work_dir_var,
        width=50,
        fg=fg_color,
        bg=entry_color,
        insertbackground="white",
    ).grid(row=1, column=1, padx=5, pady=5)

    def select_work_dir():
        path = filedialog.askdirectory()
        if path:
            work_dir_var.set(path)

    tk.Button(
        file_frame,
        text="Browse...",
        command=select_work_dir,
        fg=fg_color,
        bg=btn_color,
        activebackground="#555555",
    ).grid(row=1, column=2, pady=5)

    # Compression Slider
    tk.Label(
        file_frame, text="Zlib Compression Level (0-9):", fg=fg_color, bg=bg_color
    ).grid(row=2, column=0, sticky="w", pady=5)
    tk.Scale(
        file_frame,
        from_=0,
        to=9,
        variable=comp_level_var,
        orient="horizontal",
        fg=fg_color,
        bg=bg_color,
        highlightthickness=0,
        showvalue=True,
    ).grid(row=2, column=1, padx=5, sticky="ew")

    # Execution Log
    log_frame = tk.LabelFrame(
        root,
        text=" Execution Log ",
        font=("Arial", 10, "bold"),
        fg=fg_color,
        bg=bg_color,
        padx=5,
        pady=5,
    )
    log_frame.pack(fill="both", expand=True, padx=20, pady=5)

    text_log = tk.Text(
        log_frame,
        wrap="word",
        height=12,
        fg="#00ff00",
        bg="#121212",
        font=("Consolas", 10),
    )
    text_log.pack(fill="both", expand=True)

    # Redirect stdout to GUI log
    logger = GuiLogger(text_log)
    sys.stdout = logger
    sys.stderr = logger

    def run_thread(target):
        threading.Thread(target=target, daemon=True).start()

    def gui_unpack():
        cff = cff_var.get()
        work = work_dir_var.get()
        if not cff or not os.path.exists(cff):
            messagebox.showerror("Error", "Please specify a valid .cff file!")
            return
        text_log.delete("1.0", tk.END)
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
        run_thread(lambda: pack_all(work, cff, level))

    # Control Buttons
    action_frame = tk.Frame(root, bg=bg_color)
    action_frame.pack(pady=10)

    tk.Button(
        action_frame,
        text="1. Unpack CFF and export TEXT",
        command=gui_unpack,
        fg=fg_color,
        bg="#1e5f1e",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=5,
        activebackground="#2e7f2e",
    ).grid(row=0, column=0, padx=10)

    tk.Button(
        action_frame,
        text="2. Import TEXT and pack CFF",
        command=gui_pack,
        fg=fg_color,
        bg="#5f1e1e",
        font=("Arial", 11, "bold"),
        padx=10,
        pady=5,
        activebackground="#7f2e2e",
    ).grid(row=0, column=1, padx=10)

    root.mainloop()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Launch GUI if no CLI arguments are supplied
        launch_gui()
    else:
        # CLI commands
        cmd = sys.argv[1]
        if cmd == "export_all":
            if len(sys.argv) < 4:
                print("Usage: python sf_loc_tool.py export_all english.cff work_folder")
            else:
                unpack_all(sys.argv[2], sys.argv[3])
        elif cmd == "pack_all":
            if len(sys.argv) < 4:
                print(
                    "Usage: python sf_loc_tool.py pack_all work_folder russian.cff [compression_level]"
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
