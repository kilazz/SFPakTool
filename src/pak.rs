//pak.rs

use crate::UiLogger;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use encoding_rs::WINDOWS_1252;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// -----------------------------------------------------------------------------
// DYNAMIC INTERACTIVE TREEVIEW ENGINE
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct TreeItem {
    pub path: String,   // Full relative path: "base/data/SFTool/main.rs"
    pub name: String,   // Node name: "main.rs"
    pub is_dir: bool,   // Is directory?
    pub indent: usize,  // Indentation level
    pub expanded: bool, // Relevant only if is_dir is true
}

pub fn generate_tree_items(file_paths: &[String]) -> Vec<TreeItem> {
    let mut dirs_set = HashSet::new();
    let mut items = Vec::new();

    // 1. Extract all implicit directory paths (Refactored to eliminate clippy's needless_range_loop warning)
    for path in file_paths {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut current = String::new();
        for part in parts.iter().take(parts.len() - 1) {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(part);
            dirs_set.insert(current.clone());
        }
    }

    // 2. Gather dirs and files into unified set
    let mut all_paths = HashSet::new();
    for dir in &dirs_set {
        all_paths.insert((dir.clone(), true));
    }
    for file in file_paths {
        all_paths.insert((file.clone(), false));
    }

    // 3. Sort alphabetically (creates pre-order hierarchical tree sequence automatically)
    let mut sorted_paths: Vec<(String, bool)> = all_paths.into_iter().collect();
    sorted_paths.sort_by(|a, b| a.0.cmp(&b.0));

    for (path, is_dir) in sorted_paths {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let name = parts.last().cloned().unwrap_or_default().to_string();
        let indent = parts.len() - 1;

        items.push(TreeItem {
            path,
            name,
            is_dir,
            indent,
            expanded: true, // Directories expanded by default
        });
    }

    items
}

fn is_visible(item: &TreeItem, items: &[TreeItem]) -> bool {
    let parts: Vec<&str> = item.path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() <= 1 {
        return true; // Root elements are always visible
    }

    let mut current = String::new();
    for part in parts.iter().take(parts.len() - 1) {
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(part);

        // Refactored to eliminate clippy's collapsible_if and redundant search
        let parent_collapsed = items
            .iter()
            .any(|it| it.is_dir && it.path == current && !it.expanded);
        if parent_collapsed {
            return false;
        }
    }
    true
}

pub fn get_visible_tree_nodes(items: &[TreeItem]) -> Vec<String> {
    let mut out = Vec::new();
    for item in items {
        if is_visible(item, items) {
            let prefix = "  ".repeat(item.indent);
            let state_icon = if item.is_dir {
                if item.expanded {
                    "▼ 📁 "
                } else {
                    "▶ 📁 "
                }
            } else {
                "  📄 "
            };
            out.push(format!("{}{}{}", prefix, state_icon, item.name));
        }
    }
    out
}

pub fn toggle_tree_node(items: &mut [TreeItem], visible_index: usize) -> bool {
    let mut visible_indices = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        if is_visible(item, items) {
            visible_indices.push(idx);
        }
    }

    // Refactored using .filter() to resolve clippy's collapsible_if warning
    if let Some(&full_idx) = visible_indices
        .get(visible_index)
        .filter(|&&idx| items[idx].is_dir)
    {
        items[full_idx].expanded = !items[full_idx].expanded;
        true
    } else {
        false
    }
}

pub fn list_directory_files(dir_path: &Path) -> io::Result<Vec<String>> {
    let mut file_list = Vec::new();
    for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
        // Refactored to eliminate clippy's collapsible_if warning
        if entry.path().is_file() {
            let rel = entry.path().strip_prefix(dir_path).unwrap();
            file_list.push(rel.to_string_lossy().replace("\\", "/"));
        }
    }
    Ok(file_list)
}

pub fn list_pak_files(pak_path: &Path) -> io::Result<Vec<String>> {
    let mut f = File::open(pak_path)?;
    let total_len = f.seek(SeekFrom::End(0))?;
    let mut file_list = Vec::new();

    if total_len >= 28 {
        f.seek(SeekFrom::Start(0))?;
        if f.read_u32::<LittleEndian>()? == 4 {
            let mut magic = [0u8; 24];
            f.read_exact(&mut magic)?;
            if magic.starts_with(b"MASSIVE PAKFILE") {
                f.seek(SeekFrom::Start(76))?;
                let num_files = f.read_u32::<LittleEndian>()?;
                f.seek(SeekFrom::Start(92))?;
                let mut name_offs = Vec::new();
                for _ in 0..num_files {
                    let _size = f.read_u32::<LittleEndian>()?;
                    let _offset = f.read_u32::<LittleEndian>()?;
                    let name_off = f.read_u32::<LittleEndian>()? & 0x00FFFFFF;
                    let dir_off = f.read_u32::<LittleEndian>()? & 0x00FFFFFF;
                    name_offs.push((name_off, dir_off));
                }

                let name_list_start = f.stream_position()?;
                for (name_off, dir_off) in name_offs {
                    let file_name =
                        read_reversed_string_sf1(&mut f, name_list_start + (name_off as u64) + 2)?;
                    // Refactored boolean logic to resolve clippy's eq_op and nonminimal_bool error
                    let dir_name = if dir_off != 0x00FFFFFF && dir_off != 0 {
                        read_reversed_string_sf1(&mut f, name_list_start + (dir_off as u64))?
                    } else {
                        String::new()
                    };
                    let full_path = if dir_name.is_empty() {
                        file_name
                    } else {
                        format!("{}\\{}", dir_name, file_name)
                    };
                    file_list.push(full_path.replace("\\", "/"));
                }
                return Ok(file_list);
            }
        }
    }

    f.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 3];
    f.read_exact(&mut magic)?;
    let version = f.read_u8()?;

    if &magic == b"PAK" && version == 1 {
        let dir_offset = f.read_u32::<LittleEndian>()?;
        let _uncomp_size = f.read_u32::<LittleEndian>()?;
        let comp_size = f.read_u32::<LittleEndian>()?;

        f.seek(SeekFrom::Start(dir_offset as u64))?;
        let mut comp_data = vec![0u8; comp_size as usize];
        f.read_exact(&mut comp_data)?;

        let mut uncomp_data = Vec::new();
        let mut decoder = ZlibDecoder::new(comp_data.as_slice());
        decoder.read_to_end(&mut uncomp_data)?;

        let mut cursor = io::Cursor::new(&uncomp_data);
        let file_count = cursor.read_i32::<LittleEndian>()?;

        for _ in 0..file_count {
            let name_len = cursor.read_i32::<LittleEndian>()?;
            let mut name_bytes = vec![0u8; name_len as usize];
            cursor.read_exact(&mut name_bytes)?;
            let (cow, _, _) = WINDOWS_1252.decode(&name_bytes);
            file_list.push(cow.into_owned().replace("\\", "/"));
            cursor.read_u32::<LittleEndian>()?;
            cursor.read_u32::<LittleEndian>()?;
        }
        return Ok(file_list);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Unsupported archive format",
    ))
}

// -----------------------------------------------------------------------------
// BATCH OPERATIONS
// -----------------------------------------------------------------------------

pub fn batch_unpack_paks(root_dir: &Path, logger: &UiLogger) -> io::Result<()> {
    logger.log(&format!("[*] Initializing batch unpack: {:?}", root_dir));
    let mut found = 0;
    for entry in WalkDir::new(root_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.path().is_file()
            && entry.path().extension().and_then(|s| s.to_str()) == Some("pak")
        {
            let pak_path = entry.path();
            let parent_dir = pak_path.parent().unwrap_or(Path::new("."));
            let file_stem = pak_path.file_stem().unwrap_or_default().to_string_lossy();
            let out_dir = parent_dir.join(format!("{}_extracted", file_stem));

            logger.log(&format!(
                "[*] Batch Extracting: {} -> {:?}",
                pak_path.file_name().unwrap_or_default().to_string_lossy(),
                out_dir
            ));
            if let Err(e) = unpack_pak(pak_path, &out_dir, logger) {
                logger.log(&format!("[!] Error unpacking {:?}: {}", pak_path, e));
            } else {
                found += 1;
            }
        }
    }
    logger.log(&format!(
        "[+] Batch unpack completed. Extracted {} archives.",
        found
    ));
    Ok(())
}

pub fn batch_pack_folders(
    root_dir: &Path,
    fmt: &str,
    comp_level: u32,
    logger: &UiLogger,
) -> io::Result<()> {
    logger.log(&format!("[*] Initializing batch pack: {:?}", root_dir));
    let mut compiled = 0;

    let entries = fs::read_dir(root_dir)?;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            let folder_name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            // Exclusive Logic: Strictly compile ONLY directories that end with "_extracted" tag
            if !folder_name.to_lowercase().ends_with("_extracted") {
                continue;
            }

            let base_name = folder_name[..folder_name.len() - 10].to_string();
            let out_pak_path = root_dir.join(format!("{}.pak", base_name));
            logger.log(&format!(
                "[*] Compiling directory {:?} -> {:?}",
                folder_name, out_pak_path
            ));

            if let Err(e) = pack_pak(&path, &out_pak_path, fmt, comp_level, logger) {
                logger.log(&format!(
                    "[!] Error packing folder {:?}: {}",
                    folder_name, e
                ));
            } else {
                compiled += 1;
            }
        }
    }
    logger.log(&format!(
        "[+] Batch pack completed. Compiled {} directories.",
        compiled
    ));
    Ok(())
}

// -----------------------------------------------------------------------------
// UNPACK ENGINE
// -----------------------------------------------------------------------------

pub fn unpack_pak(pak_path: &Path, out_dir: &Path, logger: &UiLogger) -> io::Result<()> {
    let mut f = File::open(pak_path)?;
    let total_len = f.seek(SeekFrom::End(0))?;

    if total_len >= 28 {
        f.seek(SeekFrom::Start(0))?;
        if f.read_u32::<LittleEndian>()? == 4 {
            let mut magic = [0u8; 24];
            f.read_exact(&mut magic)?;
            if magic.starts_with(b"MASSIVE PAKFILE") {
                logger.log("Detected SpellForce 1 Archive Format.");
                return unpack_sf1(&mut f, out_dir, logger);
            }
        }
    }

    f.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 3];
    f.read_exact(&mut magic)?;
    let version = f.read_u8()?;

    if &magic == b"PAK" && version == 1 {
        logger.log("Detected SpellForce 2 Archive Format.");
        return unpack_sf2(&mut f, out_dir, logger);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Unknown or invalid PAK format!",
    ))
}

fn unpack_sf2(f: &mut File, out_dir: &Path, _logger: &UiLogger) -> io::Result<()> {
    let dir_offset = f.read_u32::<LittleEndian>()?;
    let _uncomp_size = f.read_u32::<LittleEndian>()?;
    let comp_size = f.read_u32::<LittleEndian>()?;

    f.seek(SeekFrom::Start(dir_offset as u64))?;
    let mut comp_data = vec![0u8; comp_size as usize];
    f.read_exact(&mut comp_data)?;

    let mut uncomp_data = Vec::new();
    let mut decoder = ZlibDecoder::new(comp_data.as_slice());
    decoder.read_to_end(&mut uncomp_data)?;

    let mut cursor = io::Cursor::new(&uncomp_data);
    let file_count = cursor.read_i32::<LittleEndian>()?;

    for _ in 0..file_count {
        let name_len = cursor.read_i32::<LittleEndian>()?;
        let mut name_bytes = vec![0u8; name_len as usize];
        cursor.read_exact(&mut name_bytes)?;
        let (cow, _, _) = WINDOWS_1252.decode(&name_bytes);
        let filename = cow.into_owned().replace("\\", "/");

        let f_offset = cursor.read_u32::<LittleEndian>()?;
        let next_offset = cursor.read_u32::<LittleEndian>()?;
        let size = next_offset - f_offset;

        let target = out_dir.join(&filename);
        if let Some(p) = target.parent() {
            fs::create_dir_all(p)?;
        }

        let orig = f.stream_position()?;
        f.seek(SeekFrom::Start(f_offset as u64))?;
        let mut buf = vec![0u8; size as usize];
        f.read_exact(&mut buf)?;
        File::create(target)?.write_all(&buf)?;
        f.seek(SeekFrom::Start(orig))?;
    }
    Ok(())
}

fn unpack_sf1(f: &mut File, out_dir: &Path, _logger: &UiLogger) -> io::Result<()> {
    f.seek(SeekFrom::Start(76))?;
    let num_files = f.read_u32::<LittleEndian>()?;
    let _root_idx = f.read_u32::<LittleEndian>()?;
    let data_start = f.read_u32::<LittleEndian>()?;
    let _archive_size = f.read_u32::<LittleEndian>()?;

    f.seek(SeekFrom::Start(92))?;
    let mut entries = Vec::new();
    for _ in 0..num_files {
        let size = f.read_u32::<LittleEndian>()?;
        let offset = f.read_u32::<LittleEndian>()?;
        let name_off = f.read_u32::<LittleEndian>()? & 0x00FFFFFF;
        let dir_off = f.read_u32::<LittleEndian>()? & 0x00FFFFFF;
        entries.push((size, offset, name_off, dir_off));
    }

    let name_list_start = f.stream_position()?;

    for (size, offset, name_off, dir_off) in entries {
        let file_name = read_reversed_string_sf1(f, name_list_start + (name_off as u64) + 2)?;
        // Refactored boolean logic to resolve clippy's eq_op and nonminimal_bool error
        let dir_name = if dir_off != 0x00FFFFFF && dir_off != 0 {
            read_reversed_string_sf1(f, name_list_start + (dir_off as u64))?
        } else {
            String::new()
        };

        let full_path = if dir_name.is_empty() {
            file_name
        } else {
            format!("{}\\{}", dir_name, file_name)
        };
        let clean_path = full_path.replace("\\", "/");
        let target = out_dir.join(&clean_path);

        if let Some(p) = target.parent() {
            fs::create_dir_all(p)?;
        }

        let orig = f.stream_position()?;
        f.seek(SeekFrom::Start((data_start + offset) as u64))?;
        let mut buf = vec![0u8; size as usize];
        f.read_exact(&mut buf)?;
        File::create(target)?.write_all(&buf)?;
        f.seek(SeekFrom::Start(orig))?;
    }
    Ok(())
}

fn read_reversed_string_sf1(f: &mut File, offset: u64) -> io::Result<String> {
    let orig = f.stream_position()?;
    f.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    loop {
        let mut b = [0u8; 1];
        if f.read(&mut b)? == 0 || b[0] == 0 {
            break;
        }
        bytes.push(b[0]);
    }
    bytes.reverse();
    f.seek(SeekFrom::Start(orig))?;
    let (cow, _, _) = WINDOWS_1252.decode(&bytes);
    Ok(cow.into_owned())
}

// -----------------------------------------------------------------------------
// PACK ENGINE
// -----------------------------------------------------------------------------

pub fn pack_pak(
    src_dir: &Path,
    out_file: &Path,
    fmt: &str,
    comp_level: u32,
    logger: &UiLogger,
) -> io::Result<()> {
    let mut files = Vec::new();
    for entry in WalkDir::new(src_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.path().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }

    if files.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No files found to pack.",
        ));
    }

    if fmt.contains("1") {
        pack_sf1(&files, src_dir, out_file, logger)
    } else {
        pack_sf2(&files, src_dir, out_file, comp_level, logger)
    }
}

fn pack_sf2(
    files: &[PathBuf],
    src_dir: &Path,
    out_file: &Path,
    comp_level: u32,
    logger: &UiLogger,
) -> io::Result<()> {
    let mut f = File::create(out_file)?;
    f.write_all(b"PAK\x01")?;
    f.write_all(&[0u8; 12])?;

    let mut entries = Vec::new();
    for file_path in files {
        let rel_path = file_path
            .strip_prefix(src_dir)
            .unwrap()
            .to_string_lossy()
            .replace("/", "\\")
            .to_lowercase();

        let offset = f.stream_position()?;
        let mut in_f = File::open(file_path)?;
        io::copy(&mut in_f, &mut f)?;
        let size = f.stream_position()? - offset;
        entries.push((rel_path, offset as u32, size as u32));
    }

    let dir_offset = f.stream_position()? as u32;
    let mut dir_buf = Vec::new();
    dir_buf.write_i32::<LittleEndian>(entries.len() as i32)?;

    for (name, offset, size) in entries {
        let (encoded, _, _) = WINDOWS_1252.encode(&name);
        dir_buf.write_i32::<LittleEndian>(encoded.len() as i32)?;
        dir_buf.write_all(&encoded)?;
        dir_buf.write_u32::<LittleEndian>(offset)?;
        dir_buf.write_u32::<LittleEndian>(offset + size)?;
    }

    let uncomp_size = dir_buf.len() as u32;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(comp_level));
    encoder.write_all(&dir_buf)?;
    let comp_data = encoder.finish()?;
    let comp_size = comp_data.len() as u32;

    f.write_all(&comp_data)?;
    f.seek(SeekFrom::Start(4))?;
    f.write_u32::<LittleEndian>(dir_offset)?;
    f.write_u32::<LittleEndian>(uncomp_size)?;
    f.write_u32::<LittleEndian>(comp_size)?;

    logger.log(&format!(
        "SF2 Archive packed successfully: {} files.",
        files.len()
    ));
    Ok(())
}

struct Sf1Entry {
    size: u32,
    offset: u32,
    name_off: u32,
    dir_off: u32,
    fullpath: PathBuf,
}

fn pack_sf1(
    files: &[PathBuf],
    src_dir: &Path,
    out_file: &Path,
    logger: &UiLogger,
) -> io::Result<()> {
    let mut f = File::create(out_file)?;
    f.write_all(&[0u8; 92])?;

    let mut entries: Vec<Sf1Entry> = Vec::new();
    let mut name_list_buf: Vec<u8> = vec![0, 0];
    let mut dir_offsets: HashMap<String, u32> = HashMap::new();

    let mut write_reversed_string = |s: &str| -> u32 {
        let offset = name_list_buf.len() as u32;
        let (encoded, _, _) = WINDOWS_1252.encode(s);
        let mut reversed = encoded.into_owned();
        reversed.reverse();
        name_list_buf.extend_from_slice(&reversed);
        name_list_buf.push(0);
        offset
    };

    for file_path in files {
        let rel_path = file_path
            .strip_prefix(src_dir)
            .unwrap()
            .to_string_lossy()
            .replace("/", "\\")
            .to_lowercase();

        let path_obj = Path::new(&rel_path);
        let file_name = path_obj
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let dir_name = path_obj
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_string_lossy()
            .to_string();

        let mut dir_offset = 0;
        if !dir_name.is_empty() {
            if !dir_offsets.contains_key(&dir_name) {
                let off = write_reversed_string(&dir_name);
                dir_offsets.insert(dir_name.clone(), off);
            }
            dir_offset = *dir_offsets.get(&dir_name).unwrap();
        }

        let name_offset = write_reversed_string(&file_name) - 2;

        entries.push(Sf1Entry {
            size: 0,
            offset: 0,
            name_off: name_offset,
            dir_off: dir_offset,
            fullpath: file_path.clone(),
        });
    }

    let placeholders = vec![0u8; entries.len() * 16];
    f.write_all(&placeholders)?;
    f.write_all(&name_list_buf)?;

    let data_start_offset = f.stream_position()? as u32;

    for entry in &mut entries {
        let file_offset = (f.stream_position()? as u32) - data_start_offset;
        let mut in_f = File::open(&entry.fullpath)?;
        io::copy(&mut in_f, &mut f)?;

        entry.offset = file_offset;
        entry.size = (f.stream_position()? as u32) - data_start_offset - file_offset;
    }

    let archive_size = f.stream_position()? as u32;

    f.seek(SeekFrom::Start(92))?;
    for entry in &entries {
        f.write_u32::<LittleEndian>(entry.size)?;
        f.write_u32::<LittleEndian>(entry.offset)?;
        f.write_u32::<LittleEndian>(entry.name_off)?;
        f.write_u32::<LittleEndian>(entry.dir_off)?;
    }

    f.seek(SeekFrom::Start(0))?;
    f.write_u32::<LittleEndian>(4)?;

    let mut magic = b"MASSIVE PAKFILE V 4.0\r\n".to_vec();
    magic.resize(24, 0);
    f.write_all(&magic)?;
    f.write_all(&[0u8; 44])?;

    f.write_u32::<LittleEndian>(0)?;
    f.write_u32::<LittleEndian>(entries.len() as u32)?;
    f.write_u32::<LittleEndian>(0)?;
    f.write_u32::<LittleEndian>(data_start_offset)?;
    f.write_u32::<LittleEndian>(archive_size)?;

    logger.log(&format!(
        "SF1 Archive packed successfully: {} files.",
        entries.len()
    ));
    Ok(())
}
