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

/// Normalizes an extension: strips whitespace and the `*.` it is often typed with (`*.JPG` is
/// `jpg`), lowercases it. A dot inside stays: `tar.gz` is one extension. The flag and the presets
/// both go through here.
pub(crate) fn normalize_ext(ext: &str) -> String {
    ext.trim()
        .trim_start_matches('*')
        .trim_start()
        .trim_start_matches('.')
        .trim()
        .to_ascii_lowercase()
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

/// Built-in + user presets; all extensions are normalized, and an entry that names none (`*`,
/// `.`, empty) is left out — as `--include-ext` leaves it out.
pub fn load_all(user_presets_path: &Path) -> Vec<Preset> {
    let mut presets = builtin_presets();
    presets.extend(load_user_presets(user_presets_path));
    for preset in &mut presets {
        preset.extensions = preset
            .extensions
            .iter()
            .map(|ext| normalize_ext(ext))
            .filter(|ext| !ext.is_empty())
            .collect();
    }
    presets
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A preset of the user's own is read the way `--include-ext` is: `*.JPG` is `jpg`, and a dot
    /// inside an extension stays.
    #[test]
    fn a_users_preset_is_normalized_like_the_flag() {
        let dir = crate::testfixtures::ScratchDir::new("presets");
        let file = dir.path().join("presets.json");
        std::fs::write(
            &file,
            br#"[{"name": "Archives", "extensions": ["*.JPG", ".tar.gz", " ZIP ", "*", " *. 7z"]}]"#,
        )
        .unwrap();
        let archives = load_all(&file)
            .into_iter()
            .find(|preset| preset.name == "Archives")
            .expect("the user's preset is loaded");
        assert_eq!(archives.extensions, ["jpg", "tar.gz", "zip", "7z"]);
    }
}
