//! Cloud mining slot allocation.
//!
//! Each cloud instance gets a unique labeled wallet slot to prevent
//! derivation depth collisions. This module handles slot assignment,
//! collision prevention, and listing.

use std::collections::HashSet;

use crate::error::Result;
use crate::wallet::WalletCore;

use super::config::InstanceState;

/// A slot allocated for a cloud mining instance.
pub struct SlotAllocation {
    pub label: String,
    pub slot_index: u32,
}

/// Allocate N cloud mining slots, avoiding labels already used by active instances.
///
/// Algorithm:
/// - Single instance + base_label not active → use base_label directly
/// - Multiple instances → assign `{base_label}-0`, `{base_label}-1`, etc.
/// - Skip any label that is already active (running instance)
/// - Registers each label in wallet_slots via derive_webcash_secret_for_label
pub fn allocate_slots(
    wallet: &WalletCore,
    base_label: &str,
    count: usize,
    active_instances: &[InstanceState],
) -> Result<Vec<SlotAllocation>> {
    let active_labels: HashSet<&str> = active_instances.iter().map(|s| s.label.as_str()).collect();

    let mut allocations = Vec::with_capacity(count);

    if count == 1 && !active_labels.contains(base_label) {
        // Single instance, base label available — use it directly.
        let (_, slot_index) = wallet.derive_webcash_secret_for_label(base_label)?;
        allocations.push(SlotAllocation {
            label: base_label.to_string(),
            slot_index,
        });
        return Ok(allocations);
    }

    // Multiple instances (or base label is taken): assign indexed labels.
    let mut i = 0u32;
    while allocations.len() < count {
        let candidate = format!("{base_label}-{i}");
        i += 1;

        if active_labels.contains(candidate.as_str()) {
            continue;
        }

        let (_, slot_index) = wallet.derive_webcash_secret_for_label(&candidate)?;
        allocations.push(SlotAllocation {
            label: candidate,
            slot_index,
        });

        // Safety: don't loop forever
        if i > 1000 {
            return Err(crate::error::Error::InvalidFormat(
                "too many cloud mining slots".to_string(),
            ));
        }
    }

    Ok(allocations)
}

/// List all cloud mining labels (active + past) from wallet_slots.
pub fn list_cloud_labels(wallet: &WalletCore, base_label: &str) -> Result<Vec<String>> {
    let all_webcash = wallet.list_labeled_wallets("webcash")?;
    Ok(all_webcash
        .into_iter()
        .filter(|w| w.label == base_label || w.label.starts_with(&format!("{base_label}-")))
        .map(|w| w.label)
        .collect())
}

/// Check if a label is currently in use by an active instance.
pub fn is_label_active(label: &str, active_instances: &[InstanceState]) -> bool {
    active_instances.iter().any(|s| s.label == label)
}
