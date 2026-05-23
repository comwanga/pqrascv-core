use crate::policy::{HardwarePolicyContext, HardwarePolicyError, HardwarePolicyRule};

#[allow(clippy::too_many_lines, clippy::collapsible_match)]
pub fn evaluate_domain_rule(
    rule: &HardwarePolicyRule,
    ctx: &HardwarePolicyContext<'_>,
) -> Result<bool, HardwarePolicyError> {
    match rule {
        HardwarePolicyRule::RequireCheckpointIntegrity => {
            if ctx.checkpoint.is_none() {
                return Err(HardwarePolicyError::CheckpointIntegrityMissing);
            }
        }
        HardwarePolicyRule::RequireTimelineCompaction => {
            if ctx.compacted_timeline.is_none() {
                return Err(HardwarePolicyError::TimelineCompactionMissing);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}
