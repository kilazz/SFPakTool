//inspector.rs

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub fn scan_strings(path: &Path, filter: &str) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    if let Ok(mut f) = File::open(path) {
        let mut data = Vec::new();
        let _ = f.read_to_end(&mut data);

        let mut current_str = String::new();
        let mut start_offset = 0;

        for (i, &b) in data.iter().enumerate() {
            // Refactored to utilize standard .contains() range checker
            if (32..=126).contains(&b) {
                if current_str.is_empty() {
                    start_offset = i;
                }
                current_str.push(b as char);
            } else {
                // Collapsed nested if blocks
                if current_str.len() >= 4
                    && (filter.is_empty()
                        || current_str.to_lowercase().contains(&filter.to_lowercase()))
                {
                    results.push((start_offset, current_str.clone()));
                }
                current_str.clear();
            }
        }
        // Don't forget EOF string check
        if current_str.len() >= 4
            && (filter.is_empty() || current_str.to_lowercase().contains(&filter.to_lowercase()))
        {
            results.push((start_offset, current_str.clone()));
        }
    }
    results
}

pub fn read_val(path: &str, offset_str: &str, dtype: &str) -> String {
    let offset = parse_offset(offset_str);
    if let Ok(mut f) = File::open(path) {
        if f.seek(SeekFrom::Start(offset as u64)).is_err() {
            return "Bounds Error".into();
        }
        match dtype {
            "Byte" => {
                if let Ok(v) = f.read_u8() {
                    return v.to_string();
                }
            }
            "Int16" => {
                if let Ok(v) = f.read_i16::<LittleEndian>() {
                    return v.to_string();
                }
            }
            "Int32" => {
                if let Ok(v) = f.read_i32::<LittleEndian>() {
                    return v.to_string();
                }
            }
            "Float32" => {
                if let Ok(v) = f.read_f32::<LittleEndian>() {
                    return format!("{:.6}", v);
                }
            }
            "String" => {
                let mut buf = [0u8; 128];
                let _ = f.read(&mut buf);
                let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                let (cow, _, _) = encoding_rs::WINDOWS_1252.decode(&buf[..end]);
                return cow.into_owned();
            }
            _ => return "Unknown Type".into(),
        }
    }
    "Error".into()
}

pub fn write_val(
    path: &str,
    offset_str: &str,
    dtype: &str,
    new_val: &str,
) -> Result<(), std::io::Error> {
    let offset = parse_offset(offset_str);
    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    f.seek(SeekFrom::Start(offset as u64))?;

    match dtype {
        "Byte" => {
            let v = new_val.parse::<u8>().unwrap_or(0);
            f.write_u8(v)?;
        }
        "Int16" => {
            let v = new_val.parse::<i16>().unwrap_or(0);
            f.write_i16::<LittleEndian>(v)?;
        }
        "Int32" => {
            let v = new_val.parse::<i32>().unwrap_or(0);
            f.write_i32::<LittleEndian>(v)?;
        }
        "Float32" => {
            let v = new_val.parse::<f32>().unwrap_or(0.0);
            f.write_f32::<LittleEndian>(v)?;
        }
        "String" => {
            let (encoded, _, _) = encoding_rs::WINDOWS_1252.encode(new_val);
            f.write_all(&encoded)?;
            f.write_u8(0)?; // null terminator
        }
        _ => {}
    }
    Ok(())
}

fn parse_offset(s: &str) -> usize {
    let s = s.trim();
    if s.to_lowercase().starts_with("0x") {
        usize::from_str_radix(&s[2..], 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}
