"""
Demo script for BGP Security Analyzer
Demonstrates how to use the enhanced security analysis capabilities
"""

import asyncio
import datetime
from pathlib import Path
import json
import logging
from utils.security_analyzer import (
    check_suspicious_patterns, 
    add_critical_prefix,
    add_uk_telecom_asn,
    add_bad_actor_asn,
    UK_CRITICAL_PREFIXES,
    UK_TELECOM_ASNS
)
from utils.analysis import BGPAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def print_security_config():
    """Print current security configuration."""
    print("\n=== UK BGP Security Monitoring Configuration ===")
    print(f"Critical Prefixes: {len(UK_CRITICAL_PREFIXES)}")
    for prefix in sorted(UK_CRITICAL_PREFIXES):
        print(f"  - {prefix}")
        
    print(f"\nMonitored UK Telecom ASNs: {len(UK_TELECOM_ASNS)}")
    for asn in sorted(UK_TELECOM_ASNS):
        print(f"  - AS{asn}")
    
    print("\n=== Security Features ===")
    print("1. BGP hijacking detection")
    print("2. Route leak detection")
    print("3. Critical infrastructure monitoring")
    print("4. Origin AS change detection")
    print("5. More-specific prefix monitoring")
    print("6. Path validation")
    print("7. UK telecom-specific security checks")

def demo_security_checks():
    """Demonstrate security checks with sample updates."""
    print("\n=== Security Analysis Demo ===")
    
    # Mock database manager (not needed for demo)
    db_manager = None
    
    # Mock prefix history for testing
    prefix_history = {
        "195.166.0.0/16": [
            {
                'timestamp': datetime.datetime.now() - datetime.timedelta(days=1),
                'as_path': "6939,2856,2856",
                'peer_asn': "6939"
            }
        ],
        "146.227.0.0/16": [
            {
                'timestamp': datetime.datetime.now() - datetime.timedelta(days=1),
                'as_path': "3356,5607",
                'peer_asn': "3356"
            }
        ]
    }
    
    # Sample updates to test
    test_updates = [
        {
            "desc": "Normal update for UK telecom prefix",
            "timestamp": datetime.datetime.now(),
            "prefix": "195.166.0.0/16",
            "as_path": "6939,2856,2856",
            "peer_asn": "6939",
            "expected_suspicious": False
        },
        {
            "desc": "Origin AS change (potential hijack)",
            "timestamp": datetime.datetime.now(),
            "prefix": "195.166.0.0/16",
            "as_path": "6939,2856,12345",  # Different origin
            "peer_asn": "6939",
            "expected_suspicious": True
        },
        {
            "desc": "Suspicious more-specific announcement",
            "timestamp": datetime.datetime.now(),
            "prefix": "195.166.100.0/24",  # More specific than 195.166.0.0/16
            "as_path": "6939,7018,12345",
            "peer_asn": "6939",
            "expected_suspicious": True
        },
        {
            "desc": "Excessive path prepending",
            "timestamp": datetime.datetime.now(),
            "prefix": "146.227.0.0/16",
            "as_path": "3356,5607,5607,5607,5607,5607",  # Excessive prepending
            "peer_asn": "3356",
            "expected_suspicious": True
        },
        {
            "desc": "Unusual transit relationship",
            "timestamp": datetime.datetime.now(),
            "prefix": "62.172.0.0/16",
            "as_path": "3356,12345,2856",  # Unknown AS 12345 providing transit to BT
            "peer_asn": "3356",
            "expected_suspicious": True
        },
        {
            "desc": "Potential route leak",
            "timestamp": datetime.datetime.now(),
            "prefix": "80.238.0.0/16",
            "as_path": "6939,65000,2856",  # Private ASN in path
            "peer_asn": "6939",
            "expected_suspicious": True
        }
    ]
    
    # Test each update
    for i, update in enumerate(test_updates):
        print(f"\n--- Test {i+1}: {update['desc']} ---")
        
        result = check_suspicious_patterns(
            update['timestamp'],
            update['prefix'],
            update['as_path'],
            update['peer_asn'],
            prefix_history,
            db_manager
        )
        
        if result:
            print("✅ DETECTED as suspicious:")
            for reason in result['reasons']:
                print(f"  - {reason}")
        else:
            print("❌ NOT detected as suspicious")
            
        if (result and update['expected_suspicious']) or (not result and not update['expected_suspicious']):
            print("✓ This matches expected behavior")
        else:
            print("✗ This does NOT match expected behavior")
        
    print("\n=== Security Analysis Demo Complete ===")

def create_sample_data_file():
    """Create a sample BGP update data file for analysis."""
    
    import pandas as pd
    
    output_dir = Path("sample_data")
    output_dir.mkdir(exist_ok=True)
    
    # Generate sample data
    now = datetime.datetime.now()
    samples = []
    
    # Normal updates
    for i in range(50):
        timestamp = now - datetime.timedelta(minutes=i*10)
        samples.append({
            "timestamp": timestamp.isoformat(),
            "prefix": "195.166.0.0/16",
            "as_path": "6939,2856,2856",
            "peer_asn": "6939",
            "update_type": "announcement",
            "suspicious": False,
            "alert_reasons": ""
        })
        
    # Some suspicious updates
    # 1. Origin change
    samples.append({
        "timestamp": (now - datetime.timedelta(hours=2)).isoformat(),
        "prefix": "195.166.0.0/16",
        "as_path": "6939,2856,12345",
        "peer_asn": "6939",
        "update_type": "announcement",
        "suspicious": True,
        "alert_reasons": "Origin AS change for critical prefix"
    })
    
    # 2. More specific
    samples.append({
        "timestamp": (now - datetime.timedelta(hours=3)).isoformat(),
        "prefix": "195.166.100.0/24",
        "as_path": "6939,7018,12345",
        "peer_asn": "6939",
        "update_type": "announcement",
        "suspicious": True,
        "alert_reasons": "Suspicious more-specific announcement"
    })
    
    # 3. Path prepending
    samples.append({
        "timestamp": (now - datetime.timedelta(hours=4)).isoformat(),
        "prefix": "146.227.0.0/16",
        "as_path": "3356,5607,5607,5607,5607,5607",
        "peer_asn": "3356",
        "update_type": "announcement",
        "suspicious": True,
        "alert_reasons": "Excessive AS path prepending detected"
    })
    
    # Create DataFrame and save to CSV
    df = pd.DataFrame(samples)
    output_file = output_dir / "sample_bgp_data.csv"
    
    # Convert as_path column to string type with a custom representation
    # This prevents confusion between the commas in the AS path and CSV delimiters
    df['as_path'] = df['as_path'].apply(lambda x: x.replace(',', ';'))
    
    # Save to CSV with proper escaping
    df.to_csv(output_file, index=False, quoting=1)  # QUOTE_ALL mode
    
    print(f"\nCreated sample data file: {output_file}")
    return output_file

def demo_analysis():
    """Demonstrate the analysis capabilities."""
    print("\n=== BGP Analysis Demo ===")
    
    # Create sample data file
    data_file = create_sample_data_file()
    
    # Initialize analyzer
    analyzer = BGPAnalyzer("sample_data/reports")
    
    # Load and analyze data
    df = analyzer.load_data(data_file)
    results = analyzer.analyze_updates(df)
    
    # Generate report
    report_file = Path("sample_data/reports/security_report.html")
    html = analyzer.generate_security_report(results, str(report_file))
    
    print(f"\nAnalysis completed. Security report generated: {report_file}")
    print("\nKey findings:")
    
    if 'suspicious_update_count' in results:
        print(f"- {results['suspicious_update_count']} suspicious updates detected")
    
    if 'critical_prefix_update_count' in results:
        print(f"- {results['critical_prefix_update_count']} updates affecting critical UK prefixes")
    
    if 'more_specific_prefix_count' in results:
        print(f"- {results['more_specific_prefix_count']} more-specific prefix announcements")

    print("\n=== BGP Analysis Demo Complete ===")
    print(f"Check the HTML report at: {report_file}")

def main():
    """Main function to run the demo."""
    # Print security configuration
    print_security_config()
    
    # Run security checks demo
    demo_security_checks()
    
    # Run analysis demo
    demo_analysis()
    
    print("\nDemo completed successfully!")

if __name__ == "__main__":
    main()
