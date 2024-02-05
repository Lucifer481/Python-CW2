import os
import requests
from dotenv import load_dotenv

class Antivirus:
    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')

    def scan_file(self, file_path):
        # Ensure the file exists
        if not os.path.isfile(file_path):
            return "File not found."

        # Prepare the API endpoint
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': self.api_key}

        # Create a multipart-encoded request with the file
        files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}

        try:
            # Send the POST request to VirusTotal
            response = requests.post(url, params=params, files=files)

            # Check the response status code
            if response.status_code == 200:
                # Successful submission
                result = response.json()
                return f"File submitted for scanning. Scan ID: {result['scan_id']}"
            else:
                return f"Scan failed with status code: {response.status_code}"

        except Exception as e:
            return f"Error during scanning: {str(e)}"

   