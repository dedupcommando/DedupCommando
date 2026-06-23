// SPDX-License-Identifier: Apache-2.0
//! Adaptive layout of the commander screen.

use ratatui::layout::{Constraint, Layout, Rect};

/// Minimum usable width of a single panel (in terminal columns).
pub const MIN_PANEL_WIDTH: u16 = 36;

/// How many panels fit across the terminal width: a value of 1..=4.
pub fn max_panels(width: u16) -> usize {
    ((width / MIN_PANEL_WIDTH) as usize).clamp(1, 4)
}

/// Regions of the commander screen.
pub struct Regions {
    pub header: Rect,
    pub panels: Rect,
    pub status: Rect,
    pub fkeys: Rect,
}

/// Splits the screen vertically: header, panel strip, status, F-key row.
pub fn regions(area: Rect) -> Regions {
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .split(area);
    Regions {
        header: rows[0],
        panels: rows[1],
        status: rows[2],
        fkeys: rows[3],
    }
}

/// Rectangles of `count` equal-width panels inside `area`.
pub fn panel_rects(area: Rect, count: usize) -> Vec<Rect> {
    let count = count.max(1) as u32;
    let constraints: Vec<Constraint> = (0..count).map(|_| Constraint::Ratio(1, count)).collect();
    Layout::horizontal(constraints).split(area).to_vec()
}

/// Triage Board regions: 3 columns — center source (≈1/2), left and
/// right (≈1/4 each) split in half into 2 receivers each = 4 receivers.
pub struct BoardRegions {
    pub left_top: Rect,
    pub left_bot: Rect,
    pub center: Rect,
    pub right_top: Rect,
    pub right_bot: Rect,
}

/// Splits `area` for the Triage Board: center wider (1/2), sides 1/4 each, each
/// side split in half vertically.
pub fn board_regions(area: Rect) -> BoardRegions {
    let cols = Layout::horizontal([
        Constraint::Ratio(1, 4),
        Constraint::Ratio(1, 2),
        Constraint::Ratio(1, 4),
    ])
    .split(area);
    let halves = [Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)];
    let left = Layout::vertical(halves).split(cols[0]);
    let right = Layout::vertical(halves).split(cols[2]);
    BoardRegions {
        left_top: left[0],
        left_bot: left[1],
        center: cols[1],
        right_top: right[0],
        right_bot: right[1],
    }
}

#[cfg(test)]
mod tests {
    use super::{board_regions, max_panels};
    use ratatui::layout::Rect;

    #[test]
    fn max_panels_scales_with_width() {
        assert_eq!(max_panels(30), 1);
        assert_eq!(max_panels(80), 2);
        assert_eq!(max_panels(120), 3);
        assert_eq!(max_panels(200), 4);
    }

    #[test]
    fn board_regions_center_wider_with_stacked_sides() {
        let r = board_regions(Rect::new(0, 0, 200, 50));
        // Columns run left to right: left < center < right.
        assert!(r.left_top.x < r.center.x);
        assert!(r.center.x < r.right_top.x);
        // Center is wider than each side subpanel (≈1/2 vs ≈1/4).
        assert!(r.center.width > r.left_top.width);
        assert!(r.center.width > r.right_top.width);
        // Side subpanels are equal width and stacked vertically.
        assert_eq!(r.left_top.width, r.left_bot.width);
        assert_eq!(r.right_top.width, r.right_bot.width);
        assert_eq!(r.left_bot.y, r.left_top.y + r.left_top.height);
        assert_eq!(r.right_bot.y, r.right_top.y + r.right_top.height);
        // Center spans the full height of the area.
        assert_eq!(r.center.height, 50);
    }
}
