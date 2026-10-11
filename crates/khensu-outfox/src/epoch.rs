// SPDX-License-Identifier: Apache-2.0
//! Network epochs (PROTOCOL.md section 2).

pub const EPOCH_SECS: u64 = 3600;
/// Nodes accept packets for the current and previous epoch to cover this skew.
pub const MAX_CLOCK_SKEW_SECS: u64 = 120;
/// `GENESIS_TIME` is not fixed by PROTOCOL.md yet; devnets use 2026-10-09T00:00:00Z.
pub const DEVNET_GENESIS_TIME: u64 = 1_791_504_000;

pub fn network_epoch(unix_secs: u64, genesis_time: u64) -> u64 {
    unix_secs.saturating_sub(genesis_time) / EPOCH_SECS
}

pub fn epoch_start(epoch: u64, genesis_time: u64) -> u64 {
    genesis_time + epoch * EPOCH_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries() {
        let g = DEVNET_GENESIS_TIME;
        assert_eq!(network_epoch(g, g), 0);
        assert_eq!(network_epoch(g + 3599, g), 0);
        assert_eq!(network_epoch(g + 3600, g), 1);
        assert_eq!(network_epoch(g - 5, g), 0);
        assert_eq!(epoch_start(2, g), g + 7200);
    }
}
