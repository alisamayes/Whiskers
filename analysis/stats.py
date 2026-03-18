
def show_actor_distribution(agent_counts, log_source_counts):
    """Show the distribution of actors variants in the given run."""
    print("\nActor Distribution:")
    print(agent_counts)
    print("\nLog Source Distribution:")
    print(log_source_counts)


def report_generation_stats(bf, sc, fl, sqli, exfil):
    print(
        "The current log was generated with: "
        f"{bf} brute force attacks, "
        f"{sc} directory scans, "
        f"{fl} request floods, "
        f"{sqli} SQL injection attacks, and "
        f"{exfil} data exfiltration attempts."
    )

def report_detection_stats(all_alerts, detected_attack_counts, mode):

    if mode == "verbose":
            print("\n--- threat detections ---")
            by_kind = {}
            for alert in all_alerts:
                by_kind.setdefault(alert.kind, []).append(alert)

            for kind, alerts_of_kind in by_kind.items():
                print(f"\n{kind.upper()} ({len(alerts_of_kind)} total):")
                detected_attack_counts[kind] = len(alerts_of_kind)
                for alert in alerts_of_kind:
                    print(f"  ⚠ {alert}")
            print("--- end detections ---\n")
    else:
        # Summary view
        by_kind = {}
        for alert in all_alerts:
            by_kind[alert.kind] = by_kind.get(alert.kind, 0) + 1
        for kind, count in by_kind.items():
            print(f"{kind.replace('_', ' ').title()} attempts detected: {count}")
            detected_attack_counts[kind] = count


def check_detection_stats(true_counts, detected_counts):
    print("\nChecking model accuracy results. Comparing detected attack count against true attack count...")
    

    if len(detected_counts) != len(true_counts):
        print("Warning: Detected counts length does not match true counts length.")

    for attack_type in true_counts:
        detected, true = detected_counts.get(attack_type, 0), true_counts[attack_type]
        if detected > true:
            accuracy = (true / detected) * 100 if detected > 0 else 0
            print(f"{attack_type.replace('_', ' ').title()} accuracy: {accuracy:.2f}% . Over-detected {detected} attempts, but only {true} were generated.")

        elif detected < true:
            accuracy = (detected / true) * 100 if true > 0 else 0
            print(f"{attack_type.replace('_', ' ').title()} accuracy: {accuracy:.2f}% . Under-detected {detected} attempts out of {true} generated attacks.")

        else:
            print(f"{attack_type.replace('_', ' ').title()} accuracy: 100%. Detected all {true} generated attempts.")