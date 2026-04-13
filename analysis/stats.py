from __future__ import annotations


def show_actor_distribution(agent_counts, log_source_counts):
    """Show the distribution of actors variants in the given run."""
    print("\nActor Distribution:")
    print(agent_counts)
    print("\nLog Source Distribution:")
    print(log_source_counts)


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

def report_detection_stats(all_alerts, detected_attack_counts, mode, *, ml_summary=None):

    lines: list[str] = [""]
    if mode == "verbose":
            lines.append("--- threat detections ---")
            by_kind = {}
            for alert in all_alerts:
                by_kind.setdefault(alert.kind, []).append(alert)

            for kind, alerts_of_kind in by_kind.items():
                lines.append(f"\n{kind.upper()} ({len(alerts_of_kind)} total):")
                detected_attack_counts[kind] = len(alerts_of_kind)
                for alert in alerts_of_kind:
                    lines.append(f"  ⚠ {alert}")
            lines.append("--- end detections ---\n")
    else:
        # Summary view
        by_kind = {}
        for alert in all_alerts:
            by_kind[alert.kind] = by_kind.get(alert.kind, 0) + 1
        for kind, count in by_kind.items():
            if kind == "ml_anomaly":
                lines.append(f"ML isolation forest identified {count} anomalous/ hostile IPs")
            else:
                lines.append(f"{kind.replace('_', ' ').title()} attempts detected: {count}")
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
            lines.append("\n-------------- Machine Learning Behaviour Anomaly Detector --------------")
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
    log_source_counts
    ) -> str:
    """
    Takes in relevant data relating to the true and detecked counts and outputs the accuracy of each attack type
    """

    lines: list[str] = [""]

    if len(detected_counts) != len(true_counts):
        lines.append("Warning: amount of detected and true attack varieties differ in length.")
        lines.append("")

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
            lines.append(f"{label} accuracy: 100%. Detected all {true} generated attempts.")

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

    lines.append("")
    lines.append("--------------- USER DISTRIBUTION (generation / actor pool) ---------------")
    if profile_counts:
        for role, n in profile_counts.items():
            lines.append(f"- {role}: {n} users")
    else:
        lines.append("(not available)")

    lines.append("")
    lines.append("--------------- LOG LINE SOURCE DISTRIBUTION (access lines by actor) ---------------")
    if log_source_counts:
        for role, n in log_source_counts.items():
            lines.append(f"- {role}: {n} access log lines")
    else:
        lines.append("(not available — run generation with access log, or N/A if no access data)")

    return "\n".join(lines)