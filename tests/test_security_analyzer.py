import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from utils.security_analyzer import check_suspicious_patterns
from utils.db_manager import BGPDatabaseManager

class MockDBManager:
    def __init__(self):
        self.stored_updates = []

    def store_suspicious_update(self, timestamp, prefix, as_path, reasons):
        self.stored_updates.append({
            'timestamp': timestamp,
            'prefix': prefix,
            'as_path': as_path,
            'reasons': reasons
        })

def test_hijacking_detection():
    """Test cases for BGP hijacking detection"""
    db = MockDBManager()
    now = datetime.now()
    prefix_history = {}

    test_cases = [
        {
            'name': "Google DNS Hijacking Attempt",
            'prefix': "8.8.8.0/24",
            'as_path': "3356,2914,65001",  # Malicious AS announcing Google's prefix
            'expected_suspicious': True
        },
        {
            'name': "Legitimate Google Announcement",
            'prefix': "8.8.8.0/24",
            'as_path': "3356,2914,15169",  # Legitimate Google announcement
            'expected_suspicious': False
        },
        {
            'name': "Path Manipulation Attack",
            'prefix': "192.168.0.0/24",
            'as_path': "3356,65001,65001,65002",  # Duplicate ASN in path
            'expected_suspicious': True
        },
        {
            'name': "Unusual Transit Position",
            'prefix': "192.168.0.0/24",
            'as_path': "65001,65002,3356",  # Major transit near origin
            'expected_suspicious': True
        },
        {
            'name': "Multiple Origin Changes",
            'prefix': "192.168.0.0/24",
            'as_path': "3356,65003",  # New origin
            'expected_suspicious': True,
            'setup_history': [
                {'timestamp': now - timedelta(minutes=1), 'as_path': "3356,65001"}
            ]
        }
    ]

    print("\nRunning BGP Security Test Cases:")
    print("=" * 50)

    for case in test_cases:
        print(f"\nTest Case: {case['name']}")
        
        # Set up history if needed
        if 'setup_history' in case:
            prefix_history[case['prefix']] = case['setup_history']

        # Run the security check
        alert = check_suspicious_patterns(
            timestamp=now,
            prefix=case['prefix'],
            as_path=case['as_path'],
            peer_asn="64512",  # Test peer ASN
            prefix_history=prefix_history,
            db_manager=db
        )

        # Verify results
        is_suspicious = alert is not None
        if is_suspicious == case['expected_suspicious']:
            print("✅ Test Passed")
            if is_suspicious:
                print("Detected Issues:")
                for reason in alert['reasons']:
                    print(f"  - {reason}")
        else:
            print("❌ Test Failed")
            print(f"Expected suspicious: {case['expected_suspicious']}")
            print(f"Got suspicious: {is_suspicious}")
            if alert:
                print("Detected Issues:")
                for reason in alert['reasons']:
                    print(f"  - {reason}")

if __name__ == "__main__":
    test_hijacking_detection()
