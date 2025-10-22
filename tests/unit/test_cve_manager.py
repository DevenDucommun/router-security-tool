"""
Unit tests for CVE Manager
"""

import pytest
from unittest.mock import patch, Mock
from database.cve_manager import CVEManager
import json


@pytest.mark.unit
class TestCVEManagerInitialization:
    """Test CVE Manager initialization"""

    def test_init_creates_database(self, temp_db):
        """Test that initialization creates database tables"""
        manager = CVEManager(db_path=temp_db)

        # Verify tables exist
        import sqlite3

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        # Check cve_vulnerabilities table
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='cve_vulnerabilities'"
        )
        assert cursor.fetchone() is not None

        # Check vendor_products table
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='vendor_products'"
        )
        assert cursor.fetchone() is not None

        conn.close()

    def test_init_with_custom_path(self, tmp_path):
        """Test initialization with custom database path"""
        db_path = tmp_path / "custom_cve.db"
        manager = CVEManager(db_path=str(db_path))

        assert db_path.exists()


@pytest.mark.unit
class TestCVEStorage:
    """Test CVE storage operations"""

    def test_store_single_cve(self, temp_db, mock_cve_data):
        """Test storing a single CVE"""
        manager = CVEManager(db_path=temp_db)
        manager.store_cves([mock_cve_data])

        # Verify stored
        import sqlite3

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT cve_id, description, cvss_v3_score "
            "FROM cve_vulnerabilities WHERE cve_id=?",
            (mock_cve_data["cve_id"],),
        )
        result = cursor.fetchone()
        conn.close()

        assert result is not None
        assert result[0] == mock_cve_data["cve_id"]
        assert result[1] == mock_cve_data["description"]
        assert result[2] == mock_cve_data["cvss_v3_score"]

    def test_store_multiple_cves(self, temp_db):
        """Test storing multiple CVEs"""
        manager = CVEManager(db_path=temp_db)

        cves = [
            {
                "cve_id": f"CVE-2023-{i}",
                "description": f"Test CVE {i}",
                "cvss_v3_score": 5.0 + i,
                "cvss_v3_severity": "Medium",
                "cvss_v2_score": None,
                "published_date": "2023-01-01",
                "last_modified": "2023-01-01",
                "cpe_matches": [],
                "references": [],
                "raw_data": {},
            }
            for i in range(5)
        ]

        manager.store_cves(cves)

        # Verify count
        import sqlite3

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve_vulnerabilities")
        count = cursor.fetchone()[0]
        conn.close()

        assert count == 5

    def test_store_with_vendor_products(self, temp_db):
        """Test that vendor/product mappings are extracted and stored"""
        manager = CVEManager(db_path=temp_db)

        cve_data = {
            "cve_id": "CVE-2023-9999",
            "description": "Test",
            "cvss_v3_score": 7.5,
            "cvss_v3_severity": "High",
            "cvss_v2_score": None,
            "published_date": "2023-01-01",
            "last_modified": "2023-01-01",
            "cpe_matches": [
                {"criteria": "cpe:2.3:*:cisco:ios:15.0:*:*:*:*:*:*:*"}
            ],
            "references": [],
            "raw_data": {},
        }

        manager.store_cves([cve_data])

        # Verify vendor/product mapping
        import sqlite3

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT vendor, product, version FROM vendor_products "
            "WHERE cve_id=?",
            (cve_data["cve_id"],),
        )
        result = cursor.fetchone()
        conn.close()

        assert result is not None
        assert result[0] == "cisco"
        assert result[1] == "ios"
        assert result[2] == "15.0"


@pytest.mark.unit
class TestCVESearch:
    """Test CVE search operations"""

    def test_search_by_vendor_product(self, temp_db):
        """Test searching CVEs by vendor and product"""
        manager = CVEManager(db_path=temp_db)

        # Store test data
        cve_data = {
            "cve_id": "CVE-2023-TEST",
            "description": "Test vulnerability",
            "cvss_v3_score": 8.0,
            "cvss_v3_severity": "High",
            "cvss_v2_score": None,
            "published_date": "2023-01-01",
            "last_modified": "2023-01-01",
            "cpe_matches": [
                {"criteria": "cpe:2.3:*:cisco:ios:15.0:*:*:*:*:*:*:*"}
            ],
            "references": [],
            "raw_data": {},
        }
        manager.store_cves([cve_data])

        # Search
        results = manager.search_cves_by_product("cisco", "ios")

        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2023-TEST"
        assert results[0]["cvss_v3_score"] == 8.0

    def test_search_with_version(self, temp_db):
        """Test searching CVEs with specific version"""
        manager = CVEManager(db_path=temp_db)

        # Store test data with specific version
        cve_data = {
            "cve_id": "CVE-2023-VERSION",
            "description": "Version-specific vulnerability",
            "cvss_v3_score": 9.0,
            "cvss_v3_severity": "Critical",
            "cvss_v2_score": None,
            "published_date": "2023-01-01",
            "last_modified": "2023-01-01",
            "cpe_matches": [
                {"criteria": "cpe:2.3:*:linksys:wrt1900ac:1.0.0:*:*:*:*:*:*:*"}
            ],
            "references": [],
            "raw_data": {},
        }
        manager.store_cves([cve_data])

        # Search with version
        results = manager.search_cves_by_product(
            "linksys", "wrt1900ac", "1.0.0"
        )

        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2023-VERSION"

    def test_search_returns_ordered_by_severity(self, temp_db):
        """Test that search results are ordered by CVSS score"""
        manager = CVEManager(db_path=temp_db)

        # Store CVEs with different scores
        cves = []
        for i, score in enumerate([3.0, 9.0, 6.0, 7.5]):
            cves.append(
                {
                    "cve_id": f"CVE-2023-{i}",
                    "description": f"Test {i}",
                    "cvss_v3_score": score,
                    "cvss_v3_severity": "High",
                    "cvss_v2_score": None,
                    "published_date": "2023-01-01",
                    "last_modified": "2023-01-01",
                    "cpe_matches": [
                        {"criteria": "cpe:2.3:*:test:product:1.0:*:*:*:*:*:*:*"}
                    ],
                    "references": [],
                    "raw_data": {},
                }
            )
        manager.store_cves(cves)

        # Search and verify ordering
        results = manager.search_cves_by_product("test", "product")

        assert len(results) == 4
        assert results[0]["cvss_v3_score"] == 9.0
        assert results[1]["cvss_v3_score"] == 7.5
        assert results[2]["cvss_v3_score"] == 6.0
        assert results[3]["cvss_v3_score"] == 3.0


@pytest.mark.unit
class TestCVECaching:
    """Test CVE caching functionality"""

    def test_cache_search_results(self, temp_db):
        """Test that search results are cached"""
        manager = CVEManager(db_path=temp_db)

        query_params = {
            "vendor": "cisco",
            "product": "ios",
            "max_results": 100,
        }
        results = [{"cve_id": "CVE-2023-TEST"}]

        manager.cache_search_results(query_params, results)

        # Retrieve cached results
        cached = manager.get_cached_search(query_params)

        assert cached is not None
        assert len(cached) == 1
        assert cached[0]["cve_id"] == "CVE-2023-TEST"

    def test_cache_expiration(self, temp_db):
        """Test that cache expires after TTL"""
        from datetime import timedelta

        manager = CVEManager(db_path=temp_db)
        # Set cache duration to 0 for testing
        manager.cache_duration = timedelta(seconds=0)

        query_params = {"vendor": "test", "product": "test", "max_results": 10}
        results = [{"cve_id": "CVE-2023-CACHE"}]

        manager.cache_search_results(query_params, results)

        # Should be expired immediately
        import time

        time.sleep(0.1)
        cached = manager.get_cached_search(query_params)

        assert cached is None


@pytest.mark.unit
class TestDatabaseStats:
    """Test database statistics"""

    def test_get_database_stats_empty(self, temp_db):
        """Test stats with empty database"""
        manager = CVEManager(db_path=temp_db)
        stats = manager.get_database_stats()

        assert stats["total_cves"] == 0
        assert stats["total_vendors"] == 0
        assert stats["total_products"] == 0
        assert stats["critical_cves"] == 0

    def test_get_database_stats_with_data(self, temp_db):
        """Test stats with populated database"""
        manager = CVEManager(db_path=temp_db)

        # Add test data
        cves = [
            {
                "cve_id": f"CVE-2023-{i}",
                "description": f"Test {i}",
                "cvss_v3_score": 9.5 if i < 2 else 5.0,  # 2 critical
                "cvss_v3_severity": "Critical" if i < 2 else "Medium",
                "cvss_v2_score": None,
                "published_date": "2023-01-01",
                "last_modified": "2023-01-01",
                "cpe_matches": [
                    {
                        "criteria": f"cpe:2.3:*:vendor{i}:product{i}:1.0:*:*:*:*:*:*:*"
                    }
                ],
                "references": [],
                "raw_data": {},
            }
            for i in range(5)
        ]
        manager.store_cves(cves)

        stats = manager.get_database_stats()

        assert stats["total_cves"] == 5
        assert stats["total_vendors"] == 5
        assert stats["total_products"] == 5
        assert stats["critical_cves"] == 2


@pytest.mark.unit
@pytest.mark.network
class TestNVDAPIIntegration:
    """Test NVD API integration (requires mocking)"""

    @patch("database.cve_manager.requests.get")
    def test_fetch_cves_for_vendor(self, mock_get, temp_db):
        """Test fetching CVEs from NVD API"""
        # Mock API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-API",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "API test vulnerability",
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "baseSeverity": "High",
                                    }
                                }
                            ]
                        },
                        "published": "2023-01-01",
                        "lastModified": "2023-01-01",
                        "configurations": [],
                        "references": [],
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        manager = CVEManager(db_path=temp_db)
        results = manager.fetch_cves_for_vendor("test_vendor")

        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2023-API"
        assert results[0]["cvss_v3_score"] == 7.5

    @patch("database.cve_manager.requests.get")
    def test_fetch_handles_api_error(self, mock_get, temp_db):
        """Test that API errors are handled gracefully"""
        mock_get.side_effect = Exception("API Error")

        manager = CVEManager(db_path=temp_db)
        results = manager.fetch_cves_for_vendor("test_vendor")

        # Should return empty list on error
        assert results == []
