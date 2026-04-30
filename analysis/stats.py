from __future__ import annotations


def show_actor_distribution(
    agent_counts, access_log_source_counts, auth_log_source_counts
):
    """Show actor and per-log-source distributions, then return both source maps."""
    print("\nActor Distribution:")
    print(agent_counts)
    print("\nLog Source Distribution:")
    all_roles = sorted(
        set((access_log_source_counts or {}).keys())
        | set((auth_log_source_counts or {}).keys())
    )
    for role in all_roles:
        access_lines = int((access_log_source_counts or {}).get(role, 0) or 0)
        auth_lines = int((auth_log_source_counts or {}).get(role, 0) or 0)
        print(f"- {role}: {access_lines} access log lines, {auth_lines} auth log lines")
    if not all_roles:
        print("(not available)")
    return access_log_source_counts, auth_log_source_counts


def report_generation_stats(true_attack_counts):
    """
    Report the true/generated attack counts for the current log.

    """
    lines: list[str] = [""]

    if not true_attack_counts:
        lines.append("No generated attack counts were provided.")
        return "\n".join(lines)

    for kind, count in true_attack_counts.items():
        lines.append(f"{kind.replace('_', ' ').title()} attempts generated: {count}")

    return "\n".join(lines)


def report_detection_stats(
    all_alerts,
    detected_attack_counts,
    mode,
    *,
    ml_summary=None,
    enabled_sources: dict[str, bool] | None = None,
):

    lines: list[str] = [""]
    source_flags = enabled_sources or {"access": True, "auth": True, "firewall": True}
    enabled_prefixes = {
        name
        for name, enabled in source_flags.items()
        if enabled and name in {"access", "auth", "firewall"}
    }

    def include_kind(kind: str) -> bool:
        if kind in {"ml_anomaly", "ml_supervised"}:
            return True
        return any(kind.startswith(f"{prefix}_") for prefix in enabled_prefixes)

    if mode == "verbose":
        lines.append("--- threat detections ---")
        verbose_by_kind: dict[str, list[object]] = {}
        for alert in all_alerts:
            if not include_kind(alert.kind):
                continue
            verbose_by_kind.setdefault(alert.kind, []).append(alert)

        for kind, alerts_of_kind in verbose_by_kind.items():
            lines.append(f"\n{kind.upper()} ({len(alerts_of_kind)} total):")
            detected_attack_counts[kind] = len(alerts_of_kind)
            for alert in alerts_of_kind:
                lines.append(f"  ⚠ {alert}")
        lines.append("--- end detections ---\n")
    else:
        # Summary view
        summary_by_kind: dict[str, int] = {}
        for alert in all_alerts:
            if not include_kind(alert.kind):
                continue
            summary_by_kind[alert.kind] = summary_by_kind.get(alert.kind, 0) + 1
        for kind, count in summary_by_kind.items():
            if kind == "ml_anomaly":
                lines.append(
                    f"ML isolation forest identified {count} anomalous/ hostile IPs"
                )
            elif kind == "ml_supervised":
                lines.append(
                    f"ML supervised classifier identified {count} likely hostile IPs"
                )
            else:
                lines.append(
                    f"{kind.replace('_', ' ').title()} attempts detected: {count}"
                )
            detected_attack_counts[kind] = count

    if ml_summary:
        try:
            n = ml_summary.get("unique_ips")
            use_forest = ml_summary.get("use_forest")
            mad = ml_summary.get("mad_multiplier")
            flagged = ml_summary.get("flagged_ips")
        except Exception:
            n = use_forest = mad = flagged = None

        if n is not None and flagged is not None:
            lines.append(
                "\n-------------- Machine Learning Behaviour Anomaly Detector --------------"
            )
            lines.append(f"Unique IPs in this log: {n}")
            if use_forest:
                lines.append(f"Outlier sensitivity: {mad:g}× ")
            else:
                lines.append(
                    f" Only {n} IPs here — not enough for the full model. "
                    "Only IPs with very extreme attack-like behaviour were considered."
                )
            lines.append(
                f"Flagged as possible hostile IPs: {flagged} "
                f"(out of {n} unique addresses)"
            )
    return "\n".join(lines)


def report_check_stats(
    true_counts,
    detected_counts,
    ips_that_attacked,
    profile_counts,
    access_log_source_counts,
    auth_log_source_counts,
) -> str:
    """
    Takes in relevant data relating to the true and detecked counts and outputs the accuracy of each attack type
    """

    lines: list[str] = [""]

    lines.append("--------------- ACCURACY (per attack type) ---------------")

    for attack_type in true_counts:
        detected, true = detected_counts.get(attack_type, 0), true_counts[attack_type]
        label = attack_type.replace("_", " ").title()
        if detected > true:
            accuracy = (true / detected) * 100 if detected > 0 else 0
            lines.append(
                f"{label} accuracy: {accuracy:.2f}%. Over-detected {detected} attempts, but only {true} were generated."
            )
        elif detected < true:
            accuracy = (detected / true) * 100 if true > 0 else 0
            lines.append(
                f"{label} accuracy: {accuracy:.2f}%. Under-detected {detected} attempts out of {true} generated attacks."
            )
        else:
            lines.append(
                f"{label} accuracy: 100%. Detected all {true} generated attempts."
            )

    if "ml_anomaly" in detected_counts:
        hostile_count = 0
        for _ip, data in ips_that_attacked.items():
            if isinstance(data, dict) and data.get("profile") != "normal":
                hostile_count += 1
        lines.append("")
        lines.append(
            f"ML Isolation Forest detected {detected_counts['ml_anomaly']} anomalous/ hostile IPs "
            f"out of {hostile_count} total unique attacking IPs (non-normal profiles in generation metadata)."
        )
    if detected_counts.get("ml_supervised", 0) > 0:
        hostile_count = 0
        for _ip, data in ips_that_attacked.items():
            if isinstance(data, dict) and data.get("profile") != "normal":
                hostile_count += 1
        lines.append(
            f"ML Supervised classifier flagged {detected_counts['ml_supervised']} likely hostile IPs "
            f"for review (reference hostile IP count in generation metadata: {hostile_count})."
        )

    lines.append("")
    lines.append(
        "--------------- USER DISTRIBUTION (generation / actor pool) ---------------"
    )
    if profile_counts:
        for role, n in profile_counts.items():
            lines.append(f"- {role}: {n} users")
    else:
        lines.append("(not available)")

    lines.append("")
    lines.append("--------------- LOG LINE SOURCE DISTRIBUTION ---------------")
    if access_log_source_counts or auth_log_source_counts:
        all_roles = sorted(
            set((access_log_source_counts or {}).keys())
            | set((auth_log_source_counts or {}).keys())
        )
        for role in all_roles:
            access_lines = int((access_log_source_counts or {}).get(role, 0) or 0)
            auth_lines = int((auth_log_source_counts or {}).get(role, 0) or 0)
            lines.append(
                f"- {role}: {access_lines} access log lines, {auth_lines} auth log lines"
            )
    else:
        lines.append(
            "(not available — run generation with access/auth logs, or N/A if no source data)"
        )

    return "\n".join(lines)
