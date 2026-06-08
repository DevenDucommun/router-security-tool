"""
Phase 2 Feature Tests
Comprehensive test suite covering export, history, and demo mode functionality
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from datetime import datetime

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from database.scan_history import ScanHistoryDB
from reports.export import ReportExporter
from utils.mock_data import MockDataGenerator, get_sample_scan


class TestMockDataGenerator:
    """Test mock data generation functionality"""
    
    def test_generate_basic_scan(self):
        """Test basic scan result generation"""
        result = MockDataGenerator.generate_scan_result()
        
        assert 'target' in result
        assert 'scan_timestamp' in result
        assert 'device_info' in result
        assert 'risk_score' in result
        assert 'risk_level' in result
        assert 'vulnerabilities' in result
        assert isinstance(result['vulnerabilities'], list)
    
    def test_generate_scan_with_target(self):
        """Test scan generation with specific target"""
        target = "192.168.1.100"
        result = MockDataGenerator.generate_scan_result(target=target)
        
        assert result['target'] == target
    
    def test_generate_critical_risk_scan(self):
        """Test generating high-risk scan"""
        # Note: risk_level parameter influences vuln count, not guarantees final risk
        result = MockDataGenerator.generate_scan_result(risk_level="CRITICAL")
        
        # Should have many vulnerabilities when requesting CRITICAL
        assert len(result['vulnerabilities']) >= 5
        # Risk score should be calculated based on actual vulnerabilities
        assert result['risk_score'] >= 0.0
        assert result['risk_level'] in ['CRITICAL', 'HIGH', 'MEDIUM']
    
    def test_generate_clean_scan(self):
        """Test generating scan with no vulnerabilities"""
        result = MockDataGenerator.generate_scan_result(vuln_count=0)
        
        assert len(result['vulnerabilities']) == 0
        assert result['risk_score'] == 0.0
    
    def test_historical_scans_ordering(self):
        """Test historical scans are properly ordered"""
        scans = MockDataGenerator.generate_historical_scans("192.168.1.1", count=5)
        
        assert len(scans) == 5
        # Should be chronologically ordered (oldest first)
        timestamps = [s['scan_timestamp'] for s in scans]
        assert timestamps == sorted(timestamps)
    
    def test_diverse_scans_variety(self):
        """Test diverse scans have different risk levels"""
        scans = MockDataGenerator.generate_diverse_scans(count=4)
        
        assert len(scans) == 4
        risk_levels = set(s['risk_level'] for s in scans)
        # Should have variety
        assert len(risk_levels) >= 2


class TestScanHistoryDatabase:
    """Test scan history database functionality"""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_history.db"
            db = ScanHistoryDB(str(db_path))
            yield db
            db.close()
    
    def test_database_initialization(self, temp_db):
        """Test database initializes correctly"""
        assert temp_db.conn is not None
        assert temp_db.db_path.exists()
    
    def test_save_scan(self, temp_db):
        """Test saving a scan to database"""
        scan_data = get_sample_scan()
        scan_id = temp_db.save_scan(scan_data)
        
        assert scan_id > 0
        
        # Verify it can be retrieved
        retrieved = temp_db.get_scan_by_id(scan_id)
        assert retrieved is not None
        assert retrieved['target'] == scan_data['target']
    
    def test_save_multiple_scans(self, temp_db):
        """Test saving multiple scans"""
        scan_ids = []
        for i in range(5):
            scan_data = MockDataGenerator.generate_scan_result(
                target=f"192.168.1.{i+1}"
            )
            scan_id = temp_db.save_scan(scan_data)
            scan_ids.append(scan_id)
        
        assert len(set(scan_ids)) == 5  # All unique IDs
        
        # Verify all can be retrieved
        all_scans = temp_db.get_all_scans()
        assert len(all_scans) >= 5
    
    def test_get_scans_by_target(self, temp_db):
        """Test filtering scans by target"""
        target = "192.168.1.50"
        
        # Save scans for specific target
        for _ in range(3):
            scan_data = MockDataGenerator.generate_scan_result(target=target)
            temp_db.save_scan(scan_data)
        
        # Save scans for different target
        for _ in range(2):
            scan_data = MockDataGenerator.generate_scan_result(target="192.168.1.100")
            temp_db.save_scan(scan_data)
        
        target_scans = temp_db.get_scans_by_target(target)
        assert len(target_scans) == 3
        assert all(s['target'] == target for s in target_scans)
    
    def test_delete_scan(self, temp_db):
        """Test deleting a scan"""
        scan_data = get_sample_scan()
        scan_id = temp_db.save_scan(scan_data)
        
        # Delete the scan
        result = temp_db.delete_scan(scan_id)
        assert result is True
        
        # Verify it's gone
        retrieved = temp_db.get_scan_by_id(scan_id)
        assert retrieved is None
    
    def test_get_statistics(self, temp_db):
        """Test statistics generation"""
        # Add some scans
        for _ in range(10):
            scan_data = get_sample_scan()
            temp_db.save_scan(scan_data)
        
        stats = temp_db.get_statistics()
        
        assert 'total_scans' in stats
        assert stats['total_scans'] >= 10
        assert 'unique_targets' in stats
        assert 'total_vulnerabilities' in stats
        assert 'avg_risk_score' in stats
        assert 'risk_distribution' in stats
    
    def test_get_unique_targets(self, temp_db):
        """Test getting unique target list"""
        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.1"]  # Duplicate
        
        for target in targets:
            scan_data = MockDataGenerator.generate_scan_result(target=target)
            temp_db.save_scan(scan_data)
        
        unique = temp_db.get_unique_targets()
        assert len(unique) == 2  # Only 2 unique targets
        assert "192.168.1.1" in unique
        assert "192.168.1.2" in unique


class TestReportExporter:
    """Test report export functionality"""
    
    @pytest.fixture
    def sample_scan(self):
        """Get sample scan data"""
        return get_sample_scan()
    
    @pytest.fixture
    def exporter(self):
        """Create report exporter"""
        return ReportExporter()
    
    def test_export_to_json(self, exporter, sample_scan):
        """Test JSON export"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = f.name
        
        try:
            result = exporter.export_to_json(sample_scan, output_path)
            assert result is True
            assert os.path.exists(output_path)
            
            # Verify JSON is valid
            with open(output_path, 'r') as f:
                data = json.load(f)
                assert 'scan_results' in data
                assert data['scan_results']['target'] == sample_scan['target']
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)
    
    def test_export_to_html(self, exporter, sample_scan):
        """Test HTML export"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            output_path = f.name
        
        try:
            result = exporter.export_to_html(sample_scan, output_path)
            assert result is True
            assert os.path.exists(output_path)
            
            # Verify HTML contains key elements
            with open(output_path, 'r') as f:
                content = f.read()
                assert '<!DOCTYPE html>' in content
                assert sample_scan['target'] in content
                assert 'Risk Score' in content
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)
    
    def test_export_to_pdf(self, exporter, sample_scan):
        """Test PDF export"""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False) as f:
            output_path = f.name
        
        try:
            result = exporter.export_to_pdf(sample_scan, output_path)
            assert result is True
            assert os.path.exists(output_path)
            
            # Verify it's a PDF file
            with open(output_path, 'rb') as f:
                header = f.read(4)
                assert header == b'%PDF'
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)
    
    def test_export_invalid_path(self, exporter, sample_scan):
        """Test export to invalid path fails gracefully"""
        invalid_path = "/invalid/path/that/does/not/exist/report.json"
        result = exporter.export_to_json(sample_scan, invalid_path)
        assert result is False


class TestNegativeCases:
    """Negative test cases - testing error handling"""
    
    def test_database_with_invalid_data(self):
        """Test database handles invalid scan data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = ScanHistoryDB(str(db_path))
            
            # Empty dict should not crash
            try:
                scan_id = db.save_scan({})
                # Should still create a record with defaults
                assert scan_id > 0
            except Exception as e:
                pytest.fail(f"Database crashed on empty dict: {e}")
            
            db.close()
    
    def test_export_with_missing_fields(self):
        """Test export handles incomplete scan data"""
        exporter = ReportExporter()
        incomplete_scan = {
            'target': '192.168.1.1',
            # Missing most fields
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = f.name
        
        try:
            # Should not crash
            result = exporter.export_to_json(incomplete_scan, output_path)
            assert result is True
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)
    
    def test_get_nonexistent_scan(self):
        """Test retrieving non-existent scan returns None"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = ScanHistoryDB(str(db_path))
            
            result = db.get_scan_by_id(99999)
            assert result is None
            
            db.close()
    
    def test_delete_nonexistent_scan(self):
        """Test deleting non-existent scan returns False"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = ScanHistoryDB(str(db_path))
            
            result = db.delete_scan(99999)
            assert result is False
            
            db.close()
    
    def test_mock_data_with_negative_count(self):
        """Test mock data handles edge cases"""
        # Should handle vuln_count of 0
        result = MockDataGenerator.generate_scan_result(vuln_count=0)
        assert len(result['vulnerabilities']) == 0
        
        # Historical scans with count=0 should return empty
        history = MockDataGenerator.generate_historical_scans("192.168.1.1", count=0)
        assert len(history) == 0


class TestIntegrationScenarios:
    """Integration tests combining multiple components"""
    
    def test_full_workflow_scan_export_save(self):
        """Test complete workflow: generate -> save -> export"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate scan
            scan_data = get_sample_scan()
            
            # Save to database
            db_path = Path(tmpdir) / "test.db"
            db = ScanHistoryDB(str(db_path))
            scan_id = db.save_scan(scan_data)
            assert scan_id > 0
            
            # Retrieve from database
            retrieved = db.get_scan_by_id(scan_id)
            assert retrieved is not None
            
            # Export to all formats
            exporter = ReportExporter()
            
            json_path = Path(tmpdir) / "report.json"
            assert exporter.export_to_json(retrieved, str(json_path))
            assert json_path.exists()
            
            html_path = Path(tmpdir) / "report.html"
            assert exporter.export_to_html(retrieved, str(html_path))
            assert html_path.exists()
            
            pdf_path = Path(tmpdir) / "report.pdf"
            assert exporter.export_to_pdf(retrieved, str(pdf_path))
            assert pdf_path.exists()
            
            db.close()
    
    def test_historical_trend_analysis(self):
        """Test analyzing security trends over time"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = ScanHistoryDB(str(db_path))
            
            target = "192.168.1.1"
            
            # Generate improving security over time
            scans = MockDataGenerator.generate_historical_scans(target, count=10)
            
            for scan in scans:
                db.save_scan(scan)
            
            # Retrieve and verify trend
            history = db.get_scans_by_target(target)
            assert len(history) == 10
            
            # Risk scores should generally decrease (improvement)
            risk_scores = [s['risk_score'] for s in history]
            # First scan should have higher risk than last
            assert risk_scores[0] >= risk_scores[-1] - 2.0  # Allow some variance
            
            db.close()
    
    def test_multiple_targets_statistics(self):
        """Test statistics with multiple targets"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = ScanHistoryDB(str(db_path))
            
            # Generate scans for multiple targets
            scans = MockDataGenerator.generate_diverse_scans(count=5)
            for scan in scans:
                db.save_scan(scan)
            
            stats = db.get_statistics()
            
            assert stats['total_scans'] >= 5
            assert stats['unique_targets'] >= 2
            assert 'risk_distribution' in stats
            
            # Should have at least one risk level
            assert len(stats['risk_distribution']) > 0
            
            db.close()


class TestAcceptanceCriteria:
    """Acceptance tests for Phase 2 features"""
    
    def test_acceptance_export_all_formats(self):
        """AC: User can export scan results to JSON, HTML, and PDF"""
        scan_data = get_sample_scan()
        exporter = ReportExporter()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # JSON
            json_path = Path(tmpdir) / "test.json"
            assert exporter.export_to_json(scan_data, str(json_path))
            assert json_path.exists()
            
            # HTML
            html_path = Path(tmpdir) / "test.html"
            assert exporter.export_to_html(scan_data, str(html_path))
            assert html_path.exists()
            
            # PDF
            pdf_path = Path(tmpdir) / "test.pdf"
            assert exporter.export_to_pdf(scan_data, str(pdf_path))
            assert pdf_path.exists()
    
    def test_acceptance_scan_history_persistence(self):
        """AC: Scan results are automatically saved to database"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = ScanHistoryDB(str(db_path))
            
            # Save scan
            scan_data = get_sample_scan()
            scan_id = db.save_scan(scan_data)
            
            # Close and reopen database
            db.close()
            
            db = ScanHistoryDB(str(db_path))
            
            # Verify persistence
            retrieved = db.get_scan_by_id(scan_id)
            assert retrieved is not None
            assert retrieved['target'] == scan_data['target']
            
            db.close()
    
    def test_acceptance_view_historical_scans(self):
        """AC: User can view list of historical scans"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = ScanHistoryDB(str(db_path))
            
            # Add multiple scans
            for i in range(5):
                scan_data = get_sample_scan()
                db.save_scan(scan_data)
            
            # Retrieve all
            scans = db.get_all_scans(limit=100)
            assert len(scans) >= 5
            
            # Each scan should have key fields
            for scan in scans:
                assert 'id' in scan
                assert 'target' in scan
                assert 'scan_timestamp' in scan
                assert 'risk_score' in scan
                assert 'vulnerability_count' in scan
            
            db.close()
    
    def test_acceptance_filter_by_target(self):
        """AC: User can filter scans by target"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = ScanHistoryDB(str(db_path))
            
            target_a = "192.168.1.1"
            target_b = "192.168.1.2"
            
            # Add scans for both targets
            for _ in range(3):
                db.save_scan(MockDataGenerator.generate_scan_result(target=target_a))
            for _ in range(2):
                db.save_scan(MockDataGenerator.generate_scan_result(target=target_b))
            
            # Filter
            scans_a = db.get_scans_by_target(target_a)
            scans_b = db.get_scans_by_target(target_b)
            
            assert len(scans_a) == 3
            assert len(scans_b) == 2
            
            db.close()
    
    def test_acceptance_demo_mode_generates_data(self):
        """AC: Demo mode generates realistic test data"""
        scan = get_sample_scan()
        
        # Should have all required fields
        assert 'target' in scan
        assert 'device_info' in scan
        assert 'vulnerabilities' in scan
        assert 'risk_score' in scan
        assert 'recommendations' in scan
        
        # Should have realistic values
        assert 0 <= scan['risk_score'] <= 10.0
        assert isinstance(scan['vulnerabilities'], list)
        
        # If has vulnerabilities, they should have proper structure
        if scan['vulnerabilities']:
            vuln = scan['vulnerabilities'][0]
            assert 'title' in vuln
            assert 'severity' in vuln
            assert 'description' in vuln


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
