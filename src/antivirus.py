import requests
from dotenv import load_dotenv
import os

# Load API Key
load_dotenv()
api_key = os.getenv('VIRUSTOTAL_API_KEY')

def scan_file(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(url, files=files, params=params)

    if response.status_code == 200:
        scan_results = response.json()
        interpreted_results = interpret_scan_results(scan_results)
        return interpreted_results
    else:
        return f"Error: {response.status_code}"

def interpret_scan_results(scan_results):
    total_engines = scan_results.get('total', 0)
    positive_detections = scan_results.get('positives', 0)
    
    # Decision threshold (e.g., 10% of engines)
    threshold = 0.1 * total_engines

    if positive_detections > threshold:
        threat_level = 'High'
    elif positive_detections > 0:
        threat_level = 'Moderate'
    else:
        threat_level = 'None'

    detailed_results = scan_results.get('scans', {})

    # Extracting detailed results from various antivirus engines
    engine_results = {engine: info['detected'] for engine, info in detailed_results.items() if 'detected' in info}

    return {
        'threat_level': threat_level,
        'positive_detections': positive_detections,
        'total_engines': total_engines,
        'detailed_engine_results': engine_results
    }
