//! Centralized security invariants helper to prevent duplication across modules.

pub fn verify_monotonic_sequence(previous: u64, current: u64) -> Result<(), &'static str> {
    if current <= previous {
        Err("Sequence must be monotonically increasing")
    } else {
        Ok(())
    }
}

pub fn verify_epoch_continuity(
    previous_epoch: u64,
    current_epoch: u64,
) -> Result<(), &'static str> {
    if current_epoch == previous_epoch + 1 {
        Ok(())
    } else {
        Err("Epoch continuity broken")
    }
}

pub fn verify_hlc_progression(previous_hlc: u64, current_hlc: u64) -> Result<(), &'static str> {
    if current_hlc <= previous_hlc {
        Err("HLC must progress strictly forward")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonicity_checks() {
        assert!(verify_monotonic_sequence(1, 2).is_ok());
        assert!(verify_monotonic_sequence(2, 2).is_err());
        assert!(verify_monotonic_sequence(3, 2).is_err());
    }
}
