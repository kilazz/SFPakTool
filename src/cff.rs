//cff.rs

use crate::UiLogger;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use encoding_rs::WINDOWS_1252;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct ChunkManifest {
    file: String,
    id: u32,
    flag1: u16,
    flag2: u16,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    chunks: Vec<ChunkManifest>,
}

#[derive(PartialEq)]
enum ChunkFormat {
    Binary,
    StringTable,              // Format A
    DeveloperTable,           // Format C
    TableBased(usize, usize), // Format B: (num_strings, extra_bytes)
}

struct TableBasedEntry {
    id: u32,
    extra_bytes: Vec<u8>,
    strings: BTreeMap<usize, String>,
}

// -----------------------------------------------------------------------------
// FORMAT DETECTION ENGINE WITH BOUNDS PROTECTION
// -----------------------------------------------------------------------------

fn detect_format(data: &[u8]) -> ChunkFormat {
    if data.len() < 8 {
        return ChunkFormat::Binary;
    }

    let mut cursor = Cursor::new(data);
    let count = cursor.read_u32::<LittleEndian>().unwrap_or(0);
    if count == 0 || count > 200_000 {
        return ChunkFormat::Binary;
    }

    // 1. Format C (developer_table)
    let mut is_c = true;
    let mut offset = 4;
    for _ in 0..count {
        if offset + 6 > data.len() || data[offset] != 0x02 {
            is_c = false;
            break;
        }
        offset += 6;
        if offset + 4 > data.len() {
            is_c = false;
            break;
        }

        let mut len_cursor = Cursor::new(&data[offset..offset + 4]);
        let name_len = len_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
        if name_len > 100_000 || offset + 4 + name_len > data.len() {
            is_c = false;
            break;
        }
        offset += 4 + name_len;

        if offset + 4 > data.len() {
            is_c = false;
            break;
        }

        let mut key_cursor = Cursor::new(&data[offset..offset + 4]);
        let key_len = key_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
        if key_len > 1000 || offset + 4 + key_len > data.len() {
            is_c = false;
            break;
        }
        offset += 4 + key_len;
    }
    if is_c && offset == data.len() {
        return ChunkFormat::DeveloperTable;
    }

    // 2. Format A (string_table)
    let mut is_a = true;
    offset = 4;
    for _ in 0..count {
        if offset + 5 > data.len() || data[offset] != 0x01 {
            is_a = false;
            break;
        }
        offset += 1;

        let mut key_cursor = Cursor::new(&data[offset..offset + 4]);
        let key_len = key_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
        if key_len > 1000 || offset + 4 + key_len > data.len() {
            is_a = false;
            break;
        }
        offset += 4 + key_len;

        if offset + 4 > data.len() {
            is_a = false;
            break;
        }

        let mut text_cursor = Cursor::new(&data[offset..offset + 4]);
        let text_len = text_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
        if text_len > 100_000 || offset + 4 + (text_len * 2) > data.len() {
            is_a = false;
            break;
        }
        offset += 4 + (text_len * 2);
    }
    if is_a && offset == data.len() {
        return ChunkFormat::StringTable;
    }

    // 3. Format B (table_based)
    for e in 0..17 {
        for n in 1..6 {
            let mut is_b = true;
            offset = 4;
            for _ in 0..count {
                if offset + 4 + e > data.len() {
                    is_b = false;
                    break;
                }
                offset += 4 + e;
                for _ in 0..n {
                    if offset + 4 > data.len() {
                        is_b = false;
                        break;
                    }
                    let mut str_cursor = Cursor::new(&data[offset..offset + 4]);
                    let str_len =
                        str_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
                    if str_len > 100_000 || offset + 4 + (str_len * 2) > data.len() {
                        is_b = false;
                        break;
                    }
                    offset += 4 + (str_len * 2);
                }
            }
            if is_b && offset == data.len() {
                return ChunkFormat::TableBased(n, e);
            }
        }
    }

    ChunkFormat::Binary
}

// -----------------------------------------------------------------------------
// TEXT EXPORTER (Binary -> JSON)
// -----------------------------------------------------------------------------

fn export_text(data: &[u8], json_path: &Path, format: ChunkFormat) -> io::Result<()> {
    let mut cursor = Cursor::new(data);
    let count = cursor.read_u32::<LittleEndian>()?;
    let mut offset = 4;
    let mut texts: BTreeMap<String, String> = BTreeMap::new();

    match format {
        ChunkFormat::StringTable => {
            for _ in 0..count {
                offset += 1;
                let mut c = Cursor::new(&data[offset..offset + 4]);
                let key_len = c.read_u32::<LittleEndian>()? as usize;
                offset += 4;

                let key = String::from_utf8_lossy(&data[offset..offset + key_len]).into_owned();
                offset += key_len;

                let mut c = Cursor::new(&data[offset..offset + 4]);
                let text_len = c.read_u32::<LittleEndian>()? as usize;
                offset += 4;

                let u16_slice: Vec<u16> = data[offset..offset + text_len * 2]
                    .chunks_exact(2)
                    .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                    .collect();
                let text = String::from_utf16_lossy(&u16_slice);
                offset += text_len * 2;

                texts.insert(key, text);
            }
        }
        ChunkFormat::DeveloperTable => {
            for i in 0..count {
                offset += 1;
                let mut c = Cursor::new(&data[offset..offset + 4]);
                let id_val = c.read_u32::<LittleEndian>()?;
                offset += 4;

                let flag = data[offset];
                offset += 1;

                let mut c = Cursor::new(&data[offset..offset + 4]);
                let name_len = c.read_u32::<LittleEndian>()? as usize;
                offset += 4;
                let (name_cow, _, _) = WINDOWS_1252.decode(&data[offset..offset + name_len]);
                let name = name_cow.into_owned();
                offset += name_len;

                let mut c = Cursor::new(&data[offset..offset + 4]);
                let key_len = c.read_u32::<LittleEndian>()? as usize;
                offset += 4;
                let (key_cow, _, _) = WINDOWS_1252.decode(&data[offset..offset + key_len]);
                let key_str = key_cow.into_owned();
                offset += key_len;

                texts.insert(format!("{}_{}_{}_{}", i, id_val, flag, key_str), name);
            }
        }
        ChunkFormat::TableBased(num_strings, extra_bytes) => {
            for i in 0..count {
                let mut c = Cursor::new(&data[offset..offset + 4]);
                let id_val = c.read_u32::<LittleEndian>()?;
                offset += 4;

                let extra_slice = &data[offset..offset + extra_bytes];
                let extra_hex: String = extra_slice.iter().map(|b| format!("{:02x}", b)).collect();
                offset += extra_bytes;

                for s in 0..num_strings {
                    let mut c = Cursor::new(&data[offset..offset + 4]);
                    let str_len = c.read_u32::<LittleEndian>()? as usize;
                    offset += 4;

                    let u16_slice: Vec<u16> = data[offset..offset + str_len * 2]
                        .chunks_exact(2)
                        .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                        .collect();
                    let text = String::from_utf16_lossy(&u16_slice);
                    offset += str_len * 2;

                    texts.insert(format!("{}_{}_{}_str{}", i, id_val, extra_hex, s), text);
                }
            }
        }
        _ => {}
    }

    if !texts.is_empty() {
        let f = File::create(json_path)?;
        serde_json::to_writer_pretty(f, &texts)?;
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// TEXT IMPORTER (JSON -> Binary)
// -----------------------------------------------------------------------------

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn import_text(json_path: &Path, chunk_path: &Path) -> io::Result<()> {
    let json_data = fs::read_to_string(json_path)?;
    let texts: BTreeMap<String, String> = serde_json::from_str(&json_data)?;
    if texts.is_empty() {
        return Ok(());
    }

    let mut is_table_based = false;
    let mut is_developer_table = false;
    let mut num_strings = 0;

    if let Some(first_key) = texts.keys().next() {
        let parts: Vec<&str> = first_key.splitn(4, '_').collect();
        if parts.len() == 4 && parts[0].parse::<u32>().is_ok() && parts[1].parse::<u32>().is_ok() {
            // Refactored conditional logic to avoid nested collapsible if warnings
            let str_idx_opt = if parts[3].starts_with("str") {
                is_table_based = true;
                let mut max_idx = 0;
                for key in texts.keys() {
                    let k_parts: Vec<&str> = key.splitn(4, '_').collect();
                    if k_parts.len() == 4
                        && k_parts[3].starts_with("str")
                        && let Ok(str_idx) = k_parts[3][3..].parse::<usize>()
                    {
                        max_idx = max_idx.max(str_idx + 1);
                    }
                }
                Some(max_idx)
            } else {
                is_developer_table = true;
                None
            };
            if let Some(resolved_len) = str_idx_opt {
                num_strings = resolved_len;
            }
        }
    }

    let mut out = File::create(chunk_path)?;

    if is_developer_table {
        let mut entries: BTreeMap<u32, (u32, u8, String, String)> = BTreeMap::new();
        for (key, val) in &texts {
            let parts: Vec<&str> = key.splitn(4, '_').collect();
            let idx = parts[0].parse::<u32>().unwrap();
            let id_val = parts[1].parse::<u32>().unwrap();
            let flag = parts[2].parse::<u8>().unwrap();
            entries.insert(idx, (id_val, flag, val.clone(), parts[3].to_string()));
        }

        out.write_u32::<LittleEndian>(entries.len() as u32)?;
        for (_, (id_val, flag, name, dev_key)) in entries {
            out.write_u8(0x02)?;
            out.write_u32::<LittleEndian>(id_val)?;
            out.write_u8(flag)?;

            let (name_enc, _, _) = WINDOWS_1252.encode(&name);
            out.write_u32::<LittleEndian>(name_enc.len() as u32)?;
            out.write_all(&name_enc)?;

            let (key_enc, _, _) = WINDOWS_1252.encode(&dev_key);
            out.write_u32::<LittleEndian>(key_enc.len() as u32)?;
            out.write_all(&key_enc)?;
        }
    } else if is_table_based {
        let mut entries: BTreeMap<u32, TableBasedEntry> = BTreeMap::new();
        for (key, val) in &texts {
            let parts: Vec<&str> = key.splitn(4, '_').collect();
            let idx = parts[0].parse::<u32>().unwrap();
            let id_val = parts[1].parse::<u32>().unwrap();
            let extra_bytes = hex_to_bytes(parts[2]);
            let str_idx = parts[3][3..].parse::<usize>().unwrap();

            let entry = entries.entry(idx).or_insert_with(|| TableBasedEntry {
                id: id_val,
                extra_bytes,
                strings: BTreeMap::new(),
            });
            entry.strings.insert(str_idx, val.clone());
        }

        out.write_u32::<LittleEndian>(entries.len() as u32)?;
        for (_, entry) in entries {
            out.write_u32::<LittleEndian>(entry.id)?;
            out.write_all(&entry.extra_bytes)?;
            for s in 0..num_strings {
                let empty = String::new();
                let text_val = entry.strings.get(&s).unwrap_or(&empty);
                let utf16: Vec<u16> = text_val.encode_utf16().collect();

                out.write_u32::<LittleEndian>(utf16.len() as u32)?;
                for &u in &utf16 {
                    out.write_u16::<LittleEndian>(u)?;
                }
            }
        }
    } else {
        out.write_u32::<LittleEndian>(texts.len() as u32)?;
        for (key, val) in texts {
            out.write_u8(0x01)?;
            let key_bytes = key.as_bytes();
            out.write_u32::<LittleEndian>(key_bytes.len() as u32)?;
            out.write_all(key_bytes)?;

            let utf16: Vec<u16> = val.encode_utf16().collect();
            out.write_u32::<LittleEndian>(utf16.len() as u32)?;
            for u in utf16 {
                out.write_u16::<LittleEndian>(u)?;
            }
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// UNPACK ALL ENGINE
// -----------------------------------------------------------------------------

pub fn unpack_all(input: &Path, out_dir: &Path, logger: &UiLogger) -> io::Result<()> {
    fs::create_dir_all(out_dir)?;
    let json_dir = out_dir.join("texts_json");
    fs::create_dir_all(&json_dir)?;

    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;

    if data.len() < 20 || &data[0..4] != b"\x12\xdd\x72\xdd" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid CFF Signature!",
        ));
    }

    File::create(out_dir.join("header.bin"))?.write_all(&data[0..20])?;

    let mut manifest = Manifest { chunks: Vec::new() };
    let mut cursor = Cursor::new(&data);
    cursor.set_position(20);

    let mut chunk_idx = 0;
    let mut text_extracted = 0;

    while (cursor.position() as usize) < data.len() {
        let id = cursor.read_u32::<LittleEndian>()?;
        let flag1 = cursor.read_u16::<LittleEndian>()?;
        let comp_size = cursor.read_u32::<LittleEndian>()?;
        let flag2 = cursor.read_u16::<LittleEndian>()?;
        let _uncomp_size = cursor.read_u32::<LittleEndian>()?;

        let mut comp_data = vec![0u8; comp_size as usize];
        cursor.read_exact(&mut comp_data)?;

        let mut uncomp_data = Vec::new();
        let mut decoder = ZlibDecoder::new(comp_data.as_slice());

        if decoder.read_to_end(&mut uncomp_data).is_ok() {
            let chunk_name = format!("chunk_{}.dat", chunk_idx);
            let chunk_path = out_dir.join(&chunk_name);
            File::create(&chunk_path)?.write_all(&uncomp_data)?;

            manifest.chunks.push(ChunkManifest {
                file: chunk_name,
                id,
                flag1,
                flag2,
            });

            let fmt = detect_format(&uncomp_data);
            if fmt != ChunkFormat::Binary {
                let json_path = json_dir.join(format!("chunk_{}_strings.json", chunk_idx));
                if export_text(&uncomp_data, &json_path, fmt).is_ok() {
                    text_extracted += 1;
                }
            }
        } else {
            logger.log(&format!("[!] Error decompressing chunk {}", chunk_idx));
        }

        chunk_idx += 1;
    }

    let manifest_file = File::create(out_dir.join("manifest.json"))?;
    serde_json::to_writer_pretty(manifest_file, &manifest)?;

    logger.log(&format!("Unpacked {} chunks successfully.", chunk_idx));
    logger.log(&format!(
        "Exported {} text datasets to JSON.",
        text_extracted
    ));

    Ok(())
}

// -----------------------------------------------------------------------------
// PACK ALL ENGINE
// -----------------------------------------------------------------------------

pub fn pack_all(
    in_dir: &Path,
    out_file: &Path,
    comp_level: u32,
    logger: &UiLogger,
) -> io::Result<()> {
    let manifest_path = in_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "manifest.json not found!",
        ));
    }

    let manifest_data = fs::read_to_string(manifest_path)?;
    let manifest: Manifest = serde_json::from_str(&manifest_data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let json_dir = in_dir.join("texts_json");

    // Refactored with standard Option filter methods to resolve clippy's collapsible_if warnings
    let valid_entries = fs::read_dir(&json_dir).ok();
    if let Some(entries) = valid_entries {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let valid_file = path
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|name| name.starts_with("chunk_") && name.ends_with("_strings.json"));

            if let Some(file_name) = valid_file {
                let parts: Vec<&str> = file_name.split('_').collect();
                if let Some(&chunk_idx) = parts.get(1) {
                    let target_dat = in_dir.join(format!("chunk_{}.dat", chunk_idx));
                    if let Err(e) = import_text(&path, &target_dat) {
                        logger.log(&format!("[!] Error compiling {}: {}", file_name, e));
                    }
                }
            }
        }
    }

    let mut out = File::create(out_file)?;

    let mut header = Vec::new();
    File::open(in_dir.join("header.bin"))?.read_to_end(&mut header)?;
    out.write_all(&header)?;

    for chunk in manifest.chunks {
        let mut uncomp_data = Vec::new();
        File::open(in_dir.join(&chunk.file))?.read_to_end(&mut uncomp_data)?;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(comp_level));
        encoder.write_all(&uncomp_data)?;
        let comp_data = encoder.finish()?;

        out.write_u32::<LittleEndian>(chunk.id)?;
        out.write_u16::<LittleEndian>(chunk.flag1)?;
        out.write_u32::<LittleEndian>(comp_data.len() as u32)?;
        out.write_u16::<LittleEndian>(chunk.flag2)?;
        out.write_u32::<LittleEndian>(uncomp_data.len() as u32)?;

        out.write_all(&comp_data)?;
    }

    logger.log("CFF successfully packed and compiled!");
    Ok(())
}
