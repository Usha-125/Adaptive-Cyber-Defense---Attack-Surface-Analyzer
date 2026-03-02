def generate_html_report(full_report, filename="defensive_scan_report.html"):

    html_content = """
    <html>
    <head>
        <title>Cyber Defense Report</title>
        <style>
            body { font-family: Arial; background-color: #f4f4f4; }
            h1 { color: #333; }
            .critical { color: red; }
            .high { color: orange; }
            .medium { color: goldenrod; }
            .low { color: green; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            table, th, td { border: 1px solid black; padding: 8px; }
        </style>
    </head>
    <body>
    <h1>Adaptive Cyber Defense Report</h1>
    """

    for report in full_report:

        html_content += f"""
        <h2>Target: {report['target']}</h2>
        <p><strong>OS:</strong> {report['os_estimate']}</p>
        <p><strong>Total Risk Score:</strong> {report['total_risk_score']}</p>
        <p><strong>Risk Level:</strong> 
            <span class="{report['risk_level'].lower()}">
            {report['risk_level']}
            </span>
        </p>

        <h3>Detected Services</h3>
        <table>
            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
            </tr>
        """

        for result in report["results"]:
            if result["state"] == "OPEN":
                html_content += f"""
                <tr>
                    <td>{result['port']}</td>
                    <td>{result['protocol']}</td>
                    <td>{result['state']}</td>
                    <td>{result['service']}</td>
                </tr>
                """

        html_content += "</table>"

    html_content += "</body></html>"

    with open(filename, "w") as f:
        f.write(html_content)

    print("HTML Report saved to", filename)