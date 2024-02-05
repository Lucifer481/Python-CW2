import unittest
from antivirus import interpret_scan_results

class TestAntivirus(unittest.TestCase):

    def test_interpret_scan_results(self):
        # This is a mock result, structure should match the actual API response
        mock_results = {
            "total": 70,
            "positives": 10,
            "scans": {
                "McAfee": {"detected": False},
                "Kaspersky": {"detected": True},
                # ... add more for testing
            }
        }
        results = interpret_scan_results(mock_results)
        self.assertEqual(results['threat_level'], 'High')  # Adjust based on your threshold logic

if __name__ == '__main__':
    unittest.main()
