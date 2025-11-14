import requests

SPIDERFOOT_URL = "http://127.0.0.1:5001"

class SpiderFootClient:

    @staticmethod
    def start_scan(scan_name: str, target: str, use_case: str = "all"):
        url = f"{SPIDERFOOT_URL}/startscan"
        payload = {
            "scanname": scan_name,
            "scantarget": target,
            "usecase": use_case
        }

        r = requests.post(url, data=payload)
        return {"status": "started", "scan_name": scan_name, "response": r.text}

    @staticmethod
    def scan_status(scan_id: str):
        url = f"{SPIDERFOOT_URL}/scan/{scan_id}"
        r = requests.get(url)
        return r.text

    @staticmethod
    def stop_scan(scan_id: str):
        url = f"{SPIDERFOOT_URL}/scan/stop?scanid={scan_id}"
        r = requests.get(url)
        return r.text

    @staticmethod
    def scan_results(scan_id: str):
        url = f"{SPIDERFOOT_URL}/scan/results/{scan_id}"
        r = requests.get(url)
        return r.text
