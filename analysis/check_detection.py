
def check_detection(true_counts, detected_counts):
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
            

