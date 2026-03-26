
def show_actor_distribution(agent_counts, log_source_counts):
    """Show the distribution of actors variants in the given run."""
    print("\nActor Distribution:")
    print(agent_counts)
    print("\nLog Source Distribution:")
    print(log_source_counts)


def report_generation_stats(bf, sc, fl, sqli, exfil, commandi):
    print(
        "The current log was generated with: "
        f"{bf} brute force attacks, "
        f"{sc} directory scans attacks, "
        f"{fl} request floods attacks, "
        f"{sqli} SQL injection attacks "
        f"{exfil} data exfiltration attack attempts, and "
        f"{commandi} command injection attack attempts."
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
            if kind == "ml_anomaly":
                print(f"ML isolation forest identified {count} anomalous/ hostile IPs")
            else:
                print(f"{kind.replace('_', ' ').title()} attempts detected: {count}")
            detected_attack_counts[kind] = count


def check_detection_stats(true_counts, detected_counts, ips_that_attacked):
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
    
    # check ML anomaly detection separately since it doesn't have a true count in the same way
    if "ml_anomaly" in detected_counts:
        hostile_count = 0
        # total amount of unique IPs that attacked and are not normal ips
        for ip in ips_that_attacked:
            if ips_that_attacked[ip] != "normal":
                hostile_count += 1

        print(f"ML Isolation Forest detected {detected_counts['ml_anomaly']} anomalous/ hostile IPs out of {hostile_count} total unique attacking IPs.")