import requests

# API key
API_KEY = "f1b98d03dba5537ecc8563eae64551dcb89ac94e98e7edf700b25d3b4ecaf9f9"

def check_phishing_url(url):
    url_scan_url = f"https://www.virustotal.com/vtapi/v2/url/scan"
    url_report_url = f"https://www.virustotal.com/vtapi/v2/url/report"

    params = {
        'apikey': API_KEY,
        'url': url
    }

    # URL for scanning
    response_scan = requests.post(url_scan_url, data=params)
    scan_results = response_scan.json()

    if scan_results['response_code'] != 1:
        print("Error scanning URL.")
        return

    resource = scan_results['resource']

    # Check the URL scan report
    params = {'apikey': API_KEY, 'resource': resource}
    response_report = requests.get(url_report_url, params=params)
    report = response_report.json()

    if report['response_code'] != 1:
        print("Error getting report.")
        return

    print("Scan results for:", url)
    print("Scan date:", report['scan_date'])
    print("Total scans:", report['total'])
    print("Positives:", report['positives'])
    print("URL detected as phishing:", report['positives'] > 0)

if __name__ == "__main__":
    url = input("Enter the URL to check for phishing: ")
    check_phishing_url(url)