// SPDX-License-Identifier: Apache-2.0
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A preset — a named set of extensions for the scan's include filter.
/// An empty `extensions` = no filter (all files are scanned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preset {
    pub name: String,
    pub extensions: Vec<String>,
}

/// Normalizes an extension: strips whitespace and a leading dot, lowercases it.
fn normalize_ext(ext: &str) -> String {
    ext.trim().trim_start_matches('.').to_ascii_lowercase()
}

/// Built-in presets. "All" is the first one (index 0), with no filter.
pub fn builtin_presets() -> Vec<Preset> {
    let preset = |name: &str, exts: &[&str]| Preset {
        name: name.to_string(),
        extensions: exts.iter().map(|ext| ext.to_string()).collect(),
    };
    vec![
        preset("All", &[]),
        preset(
            "Images",
            &[
                "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "webp", "heic", "heif", "svg",
                "ico", "raw", "cr2", "cr3", "nef", "arw", "dng", "orf", "rw2",
            ],
        ),
        preset(
            "Office documents",
            &[
                "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "pdf", "rtf",
            ],
        ),
    ]
}

/// Loads user presets from a JSON file.
/// A missing file is normal (an empty list). Broken JSON — the list is empty + a warning
/// in the log; the application launch does not fail because of it.
pub fn load_user_presets(path: &Path) -> Vec<Preset> {
    let json = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return Vec::new(),
    };
    match serde_json::from_str::<Vec<Preset>>(&json) {
        Ok(presets) => presets,
        Err(err) => {
            tracing::warn!(
                "failed to parse {}: {err}",
                crate::textsan::terminal(&path.display().to_string())
            );
            Vec::new()
        }
    }
}

/// Built-in + user presets; all extensions are normalized.
pub fn load_all(user_presets_path: &Path) -> Vec<Preset> {
    let mut presets = builtin_presets();
    presets.extend(load_user_presets(user_presets_path));
    for preset in &mut presets {
        for ext in &mut preset.extensions {
            *ext = normalize_ext(ext);
        }
    }
    presets
}
