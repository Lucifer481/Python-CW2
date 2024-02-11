import unittest
from antivirus import interpret_scan_results

class TestAntivirus(unittest.TestCase):

    def test_high_threat_level(self):
        mock_results = {
            "total": 70,
            "positives": 15, 
            "scans": {
                "McAfee": {"detected": True},
                "Kaspersky": {"detected": True},
                # Add more mock scans if needed
            }
        }
        results = interpret_scan_results(mock_results)
        self.assertEqual(results['threat_level'], 'High')

    def test_moderate_threat_level(self):
        mock_results = {
            "total": 70,
            "positives": 5,  
            "scans": {
                "McAfee": {"detected": False},
                "Kaspersky": {"detected": True},
                # Add more mock scans if needed
            }
        }
        results = interpret_scan_results(mock_results)
        self.assertEqual(results['threat_level'], 'Moderate')

    def test_no_threat_found(self):
        mock_results = {
            "total": 70,
            "positives": 0,
            "scans": {
                "McAfee": {"detected": False},
                "Kaspersky": {"detected": False},
                # Add more mock scans if needed
            }
        }
        results = interpret_scan_results(mock_results)
        self.assertEqual(results['threat_level'], 'None')

    def test_missing_keys(self):
        mock_results = {
            
        }
        results = interpret_scan_results(mock_results)
        self.assertEqual(results['threat_level'], 'None', "Should handle missing keys gracefully")


if __name__ == '__main__':
    unittest.main()
