def calculate_vulnerability_risk(vuln_data):
    score = vuln_data["cvss"]

    # Increase risk if exploit is publicly available
    if vuln_data.get("exploit_available"):
        score += 1.5

    return score


def classify_risk(total_score):
    if total_score < 5:
        return "LOW"
    elif total_score < 10:
        return "MEDIUM"
    elif total_score < 15:
        return "HIGH"
    else:
        return "CRITICAL"