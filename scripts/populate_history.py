#!/usr/bin/env python3
"""
Populate scan history database with mock data for testing.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from database.scan_history import ScanHistoryDB
from utils.mock_data import MockDataGenerator

def main():
    """Populate database with mock historical data"""
    print("🗄️  Populating scan history database with mock data...")
    
    # Initialize database
    db = ScanHistoryDB()
    
    # Generate diverse scans for multiple targets
    print("\n📊 Generating diverse scans for 5 different targets...")
    diverse_scans = MockDataGenerator.generate_diverse_scans(count=5)
    
    for scan in diverse_scans:
        scan_id = db.save_scan(scan)
        print(f"  ✅ Saved scan #{scan_id}: {scan['target']} - Risk: {scan['risk_score']}/10.0 ({scan['risk_level']})")
    
    # Generate historical scans showing improvement over time
    print("\n📈 Generating 10 historical scans for 192.168.1.1 (showing security improvement)...")
    history = MockDataGenerator.generate_historical_scans(
        target="192.168.1.1",
        count=10,
        days_back=30
    )
    
    for scan in history:
        scan_id = db.save_scan(scan)
        print(f"  ✅ Saved scan #{scan_id}: {scan['scan_timestamp'][:10]} - {scan['vulnerability_count']} vulnerabilities")
    
    # Generate more history for another target
    print("\n📈 Generating 8 historical scans for 192.168.1.254...")
    history2 = MockDataGenerator.generate_historical_scans(
        target="192.168.1.254",
        count=8,
        days_back=45
    )
    
    for scan in history2:
        scan_id = db.save_scan(scan)
        print(f"  ✅ Saved scan #{scan_id}: {scan['scan_timestamp'][:10]} - {scan['vulnerability_count']} vulnerabilities")
    
    # Display statistics
    print("\n" + "=" * 60)
    print("📊 DATABASE STATISTICS")
    print("=" * 60)
    
    stats = db.get_statistics()
    print(f"Total Scans: {stats['total_scans']}")
    print(f"Unique Targets: {stats['unique_targets']}")
    print(f"Total Vulnerabilities Found: {stats['total_vulnerabilities']}")
    print(f"Average Risk Score: {stats['avg_risk_score']}/10.0")
    print(f"\nRisk Distribution:")
    for level, count in sorted(stats['risk_distribution'].items()):
        print(f"  {level}: {count} scans")
    print(f"\nLast Scan: {stats['last_scan']}")
    
    # Show unique targets
    targets = db.get_unique_targets()
    print(f"\n🎯 Unique Targets Scanned ({len(targets)}):")
    for target in targets:
        scans_for_target = len(db.get_scans_by_target(target))
        print(f"  {target}: {scans_for_target} scan(s)")
    
    db.close()
    print("\n✅ Database population complete!")
    print(f"📁 Database location: {db.db_path}")

if __name__ == "__main__":
    main()
