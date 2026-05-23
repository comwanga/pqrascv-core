use crate::policy::{HardwarePolicyContext, HardwarePolicyError, HardwarePolicyRule};

#[allow(clippy::too_many_lines, clippy::collapsible_match)]
pub fn evaluate_domain_rule(
    _rule: &HardwarePolicyRule,
    _ctx: &HardwarePolicyContext<'_>,
) -> Result<bool, HardwarePolicyError> {
    Ok(false)
}
