
def check_detection(df, alerts):
    

    brute = detect_bruteforce(df)
    scan = detect_scanning(df)
    flood = detect_request_flood(df)

    return brute, scan, flood