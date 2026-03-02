import json

def generate_json_report(report_data, filename="defensive_scan_report.json"):
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)

    print("Report saved to", filename)