"""Deterministic cost computation from policy pricing and resource_change."""

DRIVERS = ["CloudWatchLogs", "S3Storage", "NAT_Egress", "Snapshot"]


def compute_costs(resource_change: dict, assumptions: dict, pricing_table: dict) -> dict:
    """Compute cost breakdown (deterministic).

    Formulas:
    - CloudWatchLogs: cloudwatch_log_gb_per_day * traffic_multiplier * (duration_hours/24) * cloudwatch_per_gb
    - S3Storage: s3_storage_gb * s3_per_gb * (duration_hours/720)
    - NAT_Egress: nat_egress_gb * traffic_multiplier * nat_egress_per_gb
    - Snapshot: snapshot_gb * snapshot_per_gb

    Returns:
        dict with keys: total, breakdown (list of {driver, cost, percentage}), top3_drivers (list of 3 strings)
        - breakdown sorted by cost descending
        - percentage = round(cost/total*100, 2); if total==0 then 0
    """
    duration_hours = assumptions["duration_hours"]
    traffic_multiplier = assumptions["traffic_multiplier"]

    cloudwatch_cost = (
        resource_change["cloudwatch_log_gb_per_day"]
        * traffic_multiplier
        * (duration_hours / 24)
        * pricing_table["cloudwatch_per_gb"]
    )
    s3_cost = (
        resource_change["s3_storage_gb"]
        * pricing_table["s3_per_gb"]
        * (duration_hours / 720)
    )
    nat_cost = (
        resource_change["nat_egress_gb"]
        * traffic_multiplier
        * pricing_table["nat_egress_per_gb"]
    )
    snapshot_cost = (
        resource_change["snapshot_gb"]
        * pricing_table["snapshot_per_gb"]
    )

    breakdown = [
        {"driver": "CloudWatchLogs", "cost": round(cloudwatch_cost, 2)},
        {"driver": "S3Storage", "cost": round(s3_cost, 2)},
        {"driver": "NAT_Egress", "cost": round(nat_cost, 2)},
        {"driver": "Snapshot", "cost": round(snapshot_cost, 2)},
    ]
    breakdown.sort(key=lambda x: x["cost"], reverse=True)

    total = sum(b["cost"] for b in breakdown)
    if total == 0:
        for b in breakdown:
            b["percentage"] = 0.0
    else:
        for b in breakdown:
            b["percentage"] = round(b["cost"] / total * 100, 2)

    top3_drivers = [b["driver"] for b in breakdown[:3]]
    if len(top3_drivers) < 3:
        top3_drivers.extend([DRIVERS[i] for i in range(3) if DRIVERS[i] not in top3_drivers][: 3 - len(top3_drivers)])

    return {
        "total": round(total, 2),
        "breakdown": breakdown,
        "top3_drivers": top3_drivers[:3],
    }
