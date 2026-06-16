//main.rs

slint::include_modules!();

mod cff;
mod inspector;
mod pak;

use slint::{ModelRc, SharedString, StandardListViewItem, VecModel, Weak};
use std::path::PathBuf;
use std::rc::Rc;
use std::thread;

// -----------------------------------------------------------------------------
// THREAD-SAFE UI LOGGER
// -----------------------------------------------------------------------------
#[derive(Clone)]
pub struct UiLogger {
    ui_handle: Weak<AppWindow>,
}

impl UiLogger {
    pub fn log(&self, msg: &str) {
        let msg_cloned = msg.to_string();
        let _ = self.ui_handle.upgrade_in_event_loop(move |ui| {
            let current = ui.get_log_text();
            ui.set_log_text(format!("{}{}\n", current, msg_cloned).into());
        });
    }
}

// -----------------------------------------------------------------------------
// MAIN ENTRY POINT
// -----------------------------------------------------------------------------
fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let ui_handle = ui.as_weak();

    // Explicitly initialize progress log and status bar text on startup
    ui.set_log_text("System Ready.\n".into());
    ui.set_status_msg("Ready.".into());

    // Shared state to persist tree structure on the main thread for collapse/expand
    let tree_items_state = Rc::new(std::cell::RefCell::new(Vec::<pak::TreeItem>::new()));

    // -------------------------------------------------------------------------
    // FILE DIALOG CALLBACKS WITH TREEVIEW RECONSTRUCTION
    // -------------------------------------------------------------------------
    let ui_weak_browse = ui_handle.clone();
    let tree_items_browse = tree_items_state.clone();
    ui.on_browse_file(move |ext| {
        let ext_str = ext.as_str();
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Archive/Database", &[ext_str])
            .pick_file()
        {
            let path_str = path.to_string_lossy().into_owned();

            // Refactored with isolated Option evaluation to avoid clippy's collapsible_if warning [1]
            let file_paths_opt = if ext_str == "pak" {
                pak::list_pak_files(&path).ok()
            } else {
                None
            };

            if let Some(file_paths) = file_paths_opt {
                let items = pak::generate_tree_items(&file_paths);
                let tree_strings = pak::get_visible_tree_nodes(&items);
                *tree_items_browse.borrow_mut() = items; // Update the shared state on the main thread

                let mut list_items = Vec::new();
                for t_str in tree_strings {
                    list_items.push(StandardListViewItem::from(SharedString::from(t_str)));
                }

                // Move the thread-safe Vec into the event loop closure
                let _ = ui_weak_browse.upgrade_in_event_loop(move |ui| {
                    // Instantiate the thread-unsafe Rc inside the main UI thread closure
                    let slint_model = ModelRc::from(Rc::new(VecModel::from(list_items)));
                    ui.set_archive_files(slint_model);
                });
            }
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

            // If selecting folder to pack, scan structure and generate TreeView preview
            if let Ok(file_paths) = pak::list_directory_files(&path) {
                let items = pak::generate_tree_items(&file_paths);
                let tree_strings = pak::get_visible_tree_nodes(&items);
                *tree_items_folder.borrow_mut() = items; // Update the shared state on the main thread

                let mut list_items = Vec::new();
                for t_str in tree_strings {
                    list_items.push(StandardListViewItem::from(SharedString::from(t_str)));
                }

                // Move the thread-safe Vec into the event loop closure
                let _ = ui_weak_folder.upgrade_in_event_loop(move |ui| {
                    // Instantiate the thread-unsafe Rc inside the main UI thread closure
                    let slint_model = ModelRc::from(Rc::new(VecModel::from(list_items)));
                    ui.set_archive_files(slint_model);
                });
            }
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

    // -------------------------------------------------------------------------
    // INTERACTIVE TREEVIEW CLICK EVENT CALLBACK
    // -------------------------------------------------------------------------
    let tree_items_click = tree_items_state.clone();
    let ui_weak_click = ui_handle.clone();
    ui.on_archive_item_clicked(move |visible_index| {
        if visible_index < 0 {
            return;
        }
        let mut items = tree_items_click.borrow_mut();
        if pak::toggle_tree_node(&mut items, visible_index as usize) {
            let visible_nodes = pak::get_visible_tree_nodes(&items);
            let mut list_items = Vec::new();
            for t_str in visible_nodes {
                list_items.push(StandardListViewItem::from(SharedString::from(t_str)));
            }
            let _ = ui_weak_click.upgrade_in_event_loop(move |ui| {
                let slint_model = ModelRc::from(Rc::new(VecModel::from(list_items)));
                ui.set_archive_files(slint_model);
            });
        }
    });

    // -------------------------------------------------------------------------
    // PAK ARCHIVE ENGINE CALLBACKS (INCLUDING BATCH OPERATIONS)
    // -------------------------------------------------------------------------
    let logger_pak_unpack = UiLogger {
        ui_handle: ui_handle.clone(),
    };
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

    let logger_pak_pack = UiLogger {
        ui_handle: ui_handle.clone(),
    };
    ui.on_pack_pak(move |src, out, fmt, comp| {
        let logger = logger_pak_pack.clone();
        let src_path = PathBuf::from(src.as_str());
        let out_path = PathBuf::from(out.as_str());
        let fmt_str = fmt.to_string();

        thread::spawn(move || {
            logger.log(&format!("[*] Packing directory into PAK: {:?}", src_path));
            if let Err(e) = pak::pack_pak(&src_path, &out_path, &fmt_str, comp as u32, &logger) {
                logger.log(&format!("[!] Error packing PAK: {}", e));
            } else {
                logger.log("[+] PAK Pack cycle completed successfully.");
            }
        });
    });

    let logger_batch_unpack = UiLogger {
        ui_handle: ui_handle.clone(),
    };
    ui.on_batch_unpack_pak(move |root_folder| {
        let logger = logger_batch_unpack.clone();
        let root_path = PathBuf::from(root_folder.as_str());

        thread::spawn(move || {
            if let Err(e) = pak::batch_unpack_paks(&root_path, &logger) {
                logger.log(&format!("[!] Batch Unpack Error: {}", e));
            }
        });
    });

    let logger_batch_pack = UiLogger {
        ui_handle: ui_handle.clone(),
    };
    ui.on_batch_pack_pak(move |root_folder, fmt, comp| {
        let logger = logger_batch_pack.clone();
        let root_path = PathBuf::from(root_folder.as_str());
        let fmt_str = fmt.to_string();

        thread::spawn(move || {
            if let Err(e) = pak::batch_pack_folders(&root_path, &fmt_str, comp as u32, &logger) {
                logger.log(&format!("[!] Batch Pack Error: {}", e));
            }
        });
    });

    // -------------------------------------------------------------------------
    // CFF DATABASE ENGINE CALLBACKS
    // -------------------------------------------------------------------------
    let logger_cff_unpack = UiLogger {
        ui_handle: ui_handle.clone(),
    };
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

    let logger_cff_pack = UiLogger {
        ui_handle: ui_handle.clone(),
    };
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

    // -------------------------------------------------------------------------
    // BINARY CHUNK INSPECTOR CALLBACKS
    // -------------------------------------------------------------------------
    let ui_weak = ui_handle.clone();
    ui.on_scan_binary(move |dat, filter| {
        let path = PathBuf::from(dat.as_str());
        let filter_str = filter.as_str();

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
        let val = inspector::read_val(dat.as_str(), offset.as_str(), dtype.as_str());
        val.into()
    });

    let logger_inspector = UiLogger {
        ui_handle: ui_handle.clone(),
    };
    ui.on_write_value(move |dat, offset, dtype, new_val| {
        let result = inspector::write_val(
            dat.as_str(),
            offset.as_str(),
            dtype.as_str(),
            new_val.as_str(),
        );
        if let Err(e) = result {
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
