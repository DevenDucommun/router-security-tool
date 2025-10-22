"""
CVE Database Manager
Handles CVE data fetching, caching, and querying from NIST NVD API
"""

import logging
import requests
import sqlite3
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pathlib import Path
import hashlib

logger = logging.getLogger(__name__)

class CVEManager:
    """Manages CVE database operations and NIST NVD API integration"""
    
    def __init__(self, db_path: str = "data/cve_database.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # NIST NVD API configuration
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = None  # Set via environment variable if available
        self.cache_duration = timedelta(days=1)  # Cache CVE data for 1 day
        
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database with CVE tables"""
        logger.info("Initializing CVE database")
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # CVE vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_vulnerabilities (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_v3_score REAL,
                    cvss_v3_severity TEXT,
                    cvss_v2_score REAL,
                    published_date TEXT,
                    last_modified TEXT,
                    cpe_matches TEXT,  -- JSON array of CPE matches
                    references TEXT,   -- JSON array of references
                    cached_date TEXT,
                    raw_data TEXT      -- Full CVE JSON data
                )
            """)
            
            # Vendor/product mapping table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vendor_products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vendor TEXT,
                    product TEXT,
                    version TEXT,
                    cve_id TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cve_vulnerabilities (cve_id)
                )
            """)
            
            # Search cache table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS search_cache (
                    query_hash TEXT PRIMARY KEY,
                    query_params TEXT,
                    results TEXT,
                    cached_date TEXT
                )
            """)
            
            conn.commit()
            logger.info("CVE database initialized successfully")
    
    def fetch_cves_for_vendor(self, vendor: str, product: str = None, 
                            max_results: int = 100) -> List[Dict]:
        """Fetch CVEs for a specific vendor/product from NVD API"""
        logger.info(f"Fetching CVEs for vendor: {vendor}, product: {product}")
        
        # Check cache first
        query_params = {"vendor": vendor, "product": product, "max_results": max_results}
        cached_results = self.get_cached_search(query_params)
        if cached_results:
            logger.info("Returning cached CVE results")
            return cached_results
        
        try:
            # Build API query
            params = {
                "resultsPerPage": min(max_results, 2000),  # NVD API limit
                "startIndex": 0
            }
            
            # Add vendor/product filters
            if vendor and product:
                params["cpeName"] = f"cpe:2.3:*:{vendor}:{product}:*:*:*:*:*:*:*:*"
            elif vendor:
                params["keywordSearch"] = vendor
            
            # Add API key if available
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
                
            response = requests.get(
                self.nvd_base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for vulnerability in data.get("vulnerabilities", []):
                cve_data = vulnerability.get("cve", {})
                cve_id = cve_data.get("id")
                
                if not cve_id:
                    continue
                
                # Extract CVSS scores
                cvss_v3_score = None
                cvss_v3_severity = None
                cvss_v2_score = None
                
                metrics = cve_data.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_v3_score = cvss_v3.get("baseScore")
                    cvss_v3_severity = cvss_v3.get("baseSeverity")
                elif "cvssMetricV2" in metrics:
                    cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_v2_score = cvss_v2.get("baseScore")
                
                # Extract description
                descriptions = cve_data.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                # Extract CPE matches
                configurations = cve_data.get("configurations", [])
                cpe_matches = []
                for config in configurations:
                    for node in config.get("nodes", []):
                        cpe_matches.extend(node.get("cpeMatch", []))
                
                # Extract references
                references = cve_data.get("references", [])
                
                cve_info = {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_v3_score": cvss_v3_score,
                    "cvss_v3_severity": cvss_v3_severity,
                    "cvss_v2_score": cvss_v2_score,
                    "published_date": cve_data.get("published"),
                    "last_modified": cve_data.get("lastModified"),
                    "cpe_matches": cpe_matches,
                    "references": references,
                    "raw_data": cve_data
                }
                
                cves.append(cve_info)
                
            # Store in database
            self.store_cves(cves)
            
            # Cache search results
            self.cache_search_results(query_params, cves)
            
            logger.info(f"Fetched {len(cves)} CVEs for {vendor}")
            return cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch CVEs from NVD API: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing CVE data: {e}")
            return []
    
    def store_cves(self, cves: List[Dict]):
        """Store CVE data in local database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            current_time = datetime.now().isoformat()
            
            for cve in cves:
                # Insert or update CVE
                cursor.execute("""
                    INSERT OR REPLACE INTO cve_vulnerabilities 
                    (cve_id, description, cvss_v3_score, cvss_v3_severity, 
                     cvss_v2_score, published_date, last_modified, 
                     cpe_matches, references, cached_date, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve["cve_id"],
                    cve["description"],
                    cve["cvss_v3_score"],
                    cve["cvss_v3_severity"],
                    cve["cvss_v2_score"],
                    cve["published_date"],
                    cve["last_modified"],
                    json.dumps(cve["cpe_matches"]),
                    json.dumps(cve["references"]),
                    current_time,
                    json.dumps(cve["raw_data"])
                ))
                
                # Extract and store vendor/product information
                for cpe_match in cve["cpe_matches"]:
                    cpe_uri = cpe_match.get("criteria", "")
                    if cpe_uri.startswith("cpe:2.3"):
                        parts = cpe_uri.split(":")
                        if len(parts) >= 6:
                            vendor = parts[3]
                            product = parts[4]
                            version = parts[5]
                            
                            cursor.execute("""
                                INSERT OR IGNORE INTO vendor_products 
                                (vendor, product, version, cve_id)
                                VALUES (?, ?, ?, ?)
                            """, (vendor, product, version, cve["cve_id"]))
            
            conn.commit()
    
    def search_cves_by_product(self, vendor: str, product: str, 
                             version: str = None) -> List[Dict]:
        """Search local database for CVEs affecting a specific product"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if version:
                cursor.execute("""
                    SELECT DISTINCT v.* FROM cve_vulnerabilities v
                    JOIN vendor_products vp ON v.cve_id = vp.cve_id
                    WHERE vp.vendor = ? AND vp.product = ? 
                    AND (vp.version = ? OR vp.version = '*')
                    ORDER BY v.cvss_v3_score DESC, v.published_date DESC
                """, (vendor, product, version))
            else:
                cursor.execute("""
                    SELECT DISTINCT v.* FROM cve_vulnerabilities v
                    JOIN vendor_products vp ON v.cve_id = vp.cve_id
                    WHERE vp.vendor = ? AND vp.product = ?
                    ORDER BY v.cvss_v3_score DESC, v.published_date DESC
                """, (vendor, product))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    "cve_id": row[0],
                    "description": row[1],
                    "cvss_v3_score": row[2],
                    "cvss_v3_severity": row[3],
                    "cvss_v2_score": row[4],
                    "published_date": row[5],
                    "last_modified": row[6],
                    "cpe_matches": json.loads(row[7]) if row[7] else [],
                    "references": json.loads(row[8]) if row[8] else []
                })
            
            return results
    
    def get_cached_search(self, query_params: Dict) -> Optional[List[Dict]]:
        """Check if search results are cached and still valid"""
        query_hash = hashlib.md5(json.dumps(query_params, sort_keys=True).encode()).hexdigest()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT results, cached_date FROM search_cache 
                WHERE query_hash = ?
            """, (query_hash,))
            
            result = cursor.fetchone()
            if result:
                cached_date = datetime.fromisoformat(result[1])
                if datetime.now() - cached_date < self.cache_duration:
                    return json.loads(result[0])
        
        return None
    
    def cache_search_results(self, query_params: Dict, results: List[Dict]):
        """Cache search results"""
        query_hash = hashlib.md5(json.dumps(query_params, sort_keys=True).encode()).hexdigest()
        current_time = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO search_cache 
                (query_hash, query_params, results, cached_date)
                VALUES (?, ?, ?, ?)
            """, (query_hash, json.dumps(query_params), json.dumps(results), current_time))
            conn.commit()
    
    def get_database_stats(self) -> Dict:
        """Get statistics about the CVE database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM cve_vulnerabilities")
            total_cves = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT vendor) FROM vendor_products")
            total_vendors = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT product) FROM vendor_products")
            total_products = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT COUNT(*) FROM cve_vulnerabilities 
                WHERE cvss_v3_score >= 9.0 OR cvss_v2_score >= 9.0
            """)
            critical_cves = cursor.fetchone()[0]
            
            return {
                "total_cves": total_cves,
                "total_vendors": total_vendors,
                "total_products": total_products,
                "critical_cves": critical_cves
            }

    def update_database(self, vendors: List[str] = None):
        """Update CVE database with latest data"""
        if not vendors:
            vendors = ["cisco", "linksys", "netgear", "tplink", "dlink", "asus"]
        
        logger.info(f"Updating CVE database for vendors: {vendors}")
        
        for vendor in vendors:
            try:
                logger.info(f"Fetching CVEs for {vendor}")
                self.fetch_cves_for_vendor(vendor, max_results=1000)
                time.sleep(1)  # Rate limiting
            except Exception as e:
                logger.error(f"Failed to update CVEs for {vendor}: {e}")
        
        stats = self.get_database_stats()
        logger.info(f"CVE database update complete: {stats}")
        return stats