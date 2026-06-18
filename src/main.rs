slint::include_modules!();

mod cff;
mod inspector;
mod pak;

use slint::{ModelRc, SharedString, StandardListViewItem, VecModel};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

#[derive(Clone)]
pub struct UiLogger {
    sender: mpsc::Sender<String>,
}

impl UiLogger {
    pub fn log(&self, msg: &str) {
        // Send the log message through the channel (non-blocking)
        let _ = self.sender.send(format!("{}\n", msg));
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let ui_handle = ui.as_weak();

    ui.set_log_text("System Ready.\n".into());
    ui.set_status_msg("Ready.".into());

    // Channel for fast and non-blocking log transmission to the UI
    let (log_tx, log_rx) = mpsc::channel::<String>();
    let logger_base = UiLogger { sender: log_tx };

    let ui_weak_log = ui_handle.clone();

    // Background thread for batching logs to prevent UI freezing (Quadratic complexity fix)
    thread::spawn(move || {
        let mut logs = VecDeque::with_capacity(300);
        while let Ok(msg) = log_rx.recv() {
            logs.push_back(msg);

            // Drain the channel for any pending messages
            while let Ok(m) = log_rx.try_recv() {
                logs.push_back(m);
            }

            // Keep only the last 250 lines to prevent memory bloat and UI lag
            while logs.len() > 250 {
                logs.pop_front();
            }

            let combined = logs.iter().cloned().collect::<String>();
            let _ = ui_weak_log.upgrade_in_event_loop(move |ui| {
                ui.set_log_text(combined.into());
            });

            // Refresh UI every 60ms to guarantee smooth animations
            thread::sleep(std::time::Duration::from_millis(60));
        }
    });

    // Wrapped in Arc<Mutex> for thread-safe access between background parsing and the UI
    let tree_items_state = Arc::new(Mutex::new(Vec::<pak::TreeItem>::new()));

    let ui_weak_browse = ui_handle.clone();
    let tree_items_browse = tree_items_state.clone();
    ui.on_browse_file(move |ext| {
        let ext_str = ext.as_str();
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Archive/Database", &[ext_str])
            .pick_file()
        {
            let path_str = path.to_string_lossy().into_owned();
            let ui_weak = ui_weak_browse.clone();
            let tree_state = tree_items_browse.clone();
            let ext_clone = ext_str.to_string();

            // Offload parsing to a background thread to keep UI responsive
            thread::spawn(move || {
                if ext_clone == "pak"
                    && let Ok(file_paths) = pak::list_pak_files(&path)
                {
                    let items = pak::generate_tree_items(&file_paths);
                    let tree_strings = pak::get_visible_tree_nodes(&items);

                    *tree_state.lock().unwrap() = items;

                    let list_items: Vec<_> = tree_strings
                        .into_iter()
                        .map(|s| StandardListViewItem::from(SharedString::from(s)))
                        .collect();

                    let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                        let slint_model = ModelRc::from(Rc::new(VecModel::from(list_items)));
                        ui.set_archive_files(slint_model);
                    });
                }
            });
            SharedString::from(path_str)
        } else {
            SharedString::new()
        }
    });

    let ui_weak_folder = ui_handle.clone();
    let tree_items_folder = tree_items_state.clone();
    ui.on_browse_folder(move || {
        if let Some(path) = rfd::FileDialog::new().pick_folder() {
            let path_str = path.to_string_lossy().into_owned();
            let ui_weak = ui_weak_folder.clone();
            let tree_state = tree_items_folder.clone();

            // Offload heavy directory walking to a background thread
            thread::spawn(move || {
                if let Ok(file_paths) = pak::list_directory_files(&path) {
                    let items = pak::generate_tree_items(&file_paths);
                    let tree_strings = pak::get_visible_tree_nodes(&items);

                    *tree_state.lock().unwrap() = items;

                    let list_items: Vec<_> = tree_strings
                        .into_iter()
                        .map(|t| StandardListViewItem::from(SharedString::from(t)))
                        .collect();

                    let _ = ui_weak.upgrade_in_event_loop(move |ui| {
                        let slint_model = ModelRc::from(Rc::new(VecModel::from(list_items)));
                        ui.set_archive_files(slint_model);
                    });
                }
            });
            SharedString::from(path_str)
        } else {
            SharedString::new()
        }
    });

    ui.on_save_file(|ext| {
        let ext_str = ext.as_str();
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Archive/Database", &[ext_str])
            .save_file()
        {
            SharedString::from(path.to_string_lossy().into_owned())
        } else {
            SharedString::new()
        }
    });

    let tree_items_click = tree_items_state.clone();
    let ui_weak_click = ui_handle.clone();
    ui.on_archive_item_clicked(move |visible_index| {
        if visible_index < 0 {
            return;
        }
        let mut items = tree_items_click.lock().unwrap();
        if pak::toggle_tree_node(&mut items, visible_index as usize) {
            let visible_nodes = pak::get_visible_tree_nodes(&items);
            let list_items: Vec<_> = visible_nodes
                .into_iter()
                .map(|t| StandardListViewItem::from(SharedString::from(t)))
                .collect();
            let _ = ui_weak_click.upgrade_in_event_loop(move |ui| {
                let slint_model = ModelRc::from(Rc::new(VecModel::from(list_items)));
                ui.set_archive_files(slint_model);
            });
        }
    });

    let logger_pak_unpack = logger_base.clone();
    ui.on_unpack_pak(move |input, out| {
        let logger = logger_pak_unpack.clone();
        let in_path = PathBuf::from(input.as_str());
        let out_path = PathBuf::from(out.as_str());

        thread::spawn(move || {
            logger.log(&format!("[*] Unpacking PAK archive: {:?}", in_path));
            if let Err(e) = pak::unpack_pak(&in_path, &out_path, &logger) {
                logger.log(&format!("[!] Error unpacking PAK: {}", e));
            } else {
                logger.log("[+] PAK Unpack cycle completed successfully.");
            }
        });
    });

    let logger_pak_pack = logger_base.clone();
    ui.on_pack_pak(move |src, out, fmt, comp, sf1_mode| {
        let logger = logger_pak_pack.clone();
        let src_path = PathBuf::from(src.as_str());
        let out_path = PathBuf::from(out.as_str());
        let fmt_str = fmt.to_string();
        let sf1_mode_str = sf1_mode.to_string();

        thread::spawn(move || {
            logger.log(&format!("[*] Packing directory into PAK: {:?}", src_path));
            if let Err(e) = pak::pack_pak(
                &src_path,
                &out_path,
                &fmt_str,
                comp as u32,
                &sf1_mode_str,
                &logger,
            ) {
                logger.log(&format!("[!] Error packing PAK: {}", e));
            } else {
                logger.log("[+] PAK Pack cycle completed successfully.");
            }
        });
    });

    let logger_batch_unpack = logger_base.clone();
    ui.on_batch_unpack_pak(move |root_folder| {
        let logger = logger_batch_unpack.clone();
        let root_path = PathBuf::from(root_folder.as_str());

        thread::spawn(move || {
            if let Err(e) = pak::batch_unpack_paks(&root_path, &logger) {
                logger.log(&format!("[!] Batch Unpack Error: {}", e));
            }
        });
    });

    let logger_batch_pack = logger_base.clone();
    ui.on_batch_pack_pak(move |root_folder, fmt, comp, sf1_mode| {
        let logger = logger_batch_pack.clone();
        let root_path = PathBuf::from(root_folder.as_str());
        let fmt_str = fmt.to_string();
        let sf1_mode_str = sf1_mode.to_string();

        thread::spawn(move || {
            if let Err(e) =
                pak::batch_pack_folders(&root_path, &fmt_str, comp as u32, &sf1_mode_str, &logger)
            {
                logger.log(&format!("[!] Batch Pack Error: {}", e));
            }
        });
    });

    let logger_cff_unpack = logger_base.clone();
    ui.on_unpack_cff(move |input, out| {
        let logger = logger_cff_unpack.clone();
        let in_path = PathBuf::from(input.as_str());
        let out_path = PathBuf::from(out.as_str());

        thread::spawn(move || {
            logger.log(&format!(
                "[*] Processing CFF full unpack & JSON export: {:?}",
                in_path
            ));
            if let Err(e) = cff::unpack_all(&in_path, &out_path, &logger) {
                logger.log(&format!("[!] Error processing CFF: {}", e));
            } else {
                logger.log("[+] CFF Unpack cycle completed successfully.");
            }
        });
    });

    let logger_cff_pack = logger_base.clone();
    ui.on_pack_cff(move |input, out, comp| {
        let logger = logger_cff_pack.clone();
        let in_path = PathBuf::from(input.as_str());
        let out_path = PathBuf::from(out.as_str());

        thread::spawn(move || {
            logger.log(&format!(
                "[*] Compiling JSON texts and packing CFF from: {:?}",
                in_path
            ));
            if let Err(e) = cff::pack_all(&in_path, &out_path, comp as u32, &logger) {
                logger.log(&format!("[!] Error packing CFF: {}", e));
            } else {
                logger.log("[+] CFF Pack cycle completed successfully.");
            }
        });
    });

    let ui_weak = ui_handle.clone();
    ui.on_scan_binary(move |dat, filter| {
        let path = PathBuf::from(dat.as_str());
        let filter_str = filter.as_str();

        // This is fast enough to block UI slightly, but ideally could be spawned too if needed.
        let items = inspector::scan_strings(&path, filter_str);

        let mut slint_items: Vec<StandardListViewItem> = Vec::new();
        for (offset, val) in items {
            let text = format!("0x{:04X} ({}) | {}", offset, offset, val);
            slint_items.push(StandardListViewItem::from(SharedString::from(text)));
        }

        let _ = ui_weak.upgrade_in_event_loop(move |ui| {
            let slint_model = slint::ModelRc::from(Rc::new(slint::VecModel::from(slint_items)));
            ui.set_inspector_results(slint_model);
            ui.set_status_msg("Binary scan complete.".into());
        });
    });

    ui.on_read_value(|dat, offset, dtype| {
        inspector::read_val(dat.as_str(), offset.as_str(), dtype.as_str()).into()
    });

    let logger_inspector = logger_base.clone();
    ui.on_write_value(move |dat, offset, dtype, new_val| {
        if let Err(e) = inspector::write_val(
            dat.as_str(),
            offset.as_str(),
            dtype.as_str(),
            new_val.as_str(),
        ) {
            logger_inspector.log(&format!("[!] Inspector Write Error: {}", e));
        } else {
            logger_inspector.log(&format!(
                "[+] Successfully wrote {} at offset {} to file.",
                new_val, offset
            ));
        }
    });

    ui.run()
}
