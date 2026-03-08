"""
Expected Loss / Risk Adjusted Loss. All tables from policy bundle; no hardcoding.
"""


def calculate_expected_loss(
    likelihood_table: dict,
    impact_table: dict,
    severity: str,
    scenario_class: str,
) -> float:
    """ExpectedLoss = likelihood(severity) * impact(scenario_class). Lookup from policy tables only."""
    prob = _table_value(likelihood_table, severity, 0.0)
    impact = _table_value(impact_table, scenario_class, 0.0)
    return prob * impact


def calculate_risk_adjusted_loss(
    expected_loss: float,
    regulation_weights: dict,
    weight_profile: str,
) -> float:
    """risk_adjusted_loss = expected_loss * regulation_weights[weight_profile].default."""
    profile = regulation_weights.get(weight_profile) or regulation_weights.get("normal") or {}
    mult = profile.get("default", 1.0)
    return expected_loss * mult


def _table_value(table: dict, key: str, default: float) -> float:
    """Get numeric value from table, skipping non-data keys like 'description'."""
    if key in table and isinstance(table[key], (int, float)):
        return float(table[key])
    return default
