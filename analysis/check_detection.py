
def check_detection(true_counts, detected_counts, df=None):
    print("\nChecking model accuracy results. Comparing detected attack count against true attack count...")
    
    # If a dataframe is provided, derive true counts from the label fields in the log.
    # This avoids relying on the internal "true_counts" values (which may not match a
    # pre-existing log file) and aligns with the per-instance "count" field written by
    # the log generator.
    if df is not None and not df.empty:
        true_counts_from_labels = {}

        for attack_type in true_counts.keys():
            if attack_type in ("ml_anomaly", "ml_supervised"):
                # ML detectors don't have ground truth labels in logs
                true_counts_from_labels[attack_type] = 0
                continue

            attack_logs = df[df["classification"] == attack_type]
            if attack_logs.empty:
                true_counts_from_labels[attack_type] = 0
            else:
                # Each unique "count" value in the logs represents one generated attack instance
                true_counts_from_labels[attack_type] = int(attack_logs["count"].nunique())

        actual_true_counts = true_counts_from_labels
    else:
        actual_true_counts = true_counts

    if len(detected_counts) != len(actual_true_counts):
        print("Warning: Detected counts length does not match true counts length.")

    for attack_type in actual_true_counts:
        detected, true = detected_counts.get(attack_type, 0), actual_true_counts[attack_type]
        if detected > true:
            accuracy = (true / detected) * 100 if detected > 0 else 0
            print(f"{attack_type.replace('_', ' ').title()} accuracy: {accuracy:.2f}% . Over-detected {detected} attempts, but only {true} were generated.")

        elif detected < true:
            accuracy = (detected / true) * 100 if true > 0 else 0
            print(f"{attack_type.replace('_', ' ').title()} accuracy: {accuracy:.2f}% . Under-detected {detected} attempts out of {true} generated attacks.")

        else:
            print(f"{attack_type.replace('_', ' ').title()} accuracy: 100%. Detected all {true} generated attempts.")
            

