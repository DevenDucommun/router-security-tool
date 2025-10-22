# Testing Documentation

## Test Suite Overview

The Router Security Tool has a comprehensive test suite covering all Phase 2 modules with **130 passing tests** and **61% overall code coverage**.

## Test Structure

```
tests/
├── integration/              # End-to-end workflow tests
│   └── test_vulnerability_workflow.py
└── unit/                     # Unit tests for individual modules
    ├── conftest.py          # Shared fixtures
    ├── test_cve_manager.py
    ├── test_service_scanner.py
    ├── test_vulnerability_scanner.py
    ├── test_connection_detector.py
    └── test_connection_manager.py
```

## Coverage by Module

| Module | Coverage | Lines Tested |
|--------|----------|--------------|
| Vulnerability Scanner | 96% | 194/202 |
| Connection Manager | 89% | 110/124 |
| Connection Detector | 84% | 53/63 |
| CVE Manager | 84% | 132/157 |
| Service Scanner | 70% | 169/240 |

**Note:** GUI (main_window.py) and Filesystem Scraper are at 0% coverage as they require GUI/integration testing which will be added in later phases.

## Running Tests

### Run All Tests
```bash
pytest tests/ -v
```

### Run with Coverage Report
```bash
pytest tests/ --cov=src --cov-report=html --cov-report=term
```

### Run Specific Test Module
```bash
pytest tests/unit/test_cve_manager.py -v
pytest tests/integration/test_vulnerability_workflow.py -v
```

### Run Tests by Category
```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests only
pytest tests/integration/ -v
```

## Test Categories

### Unit Tests

#### CVE Manager Tests (`test_cve_manager.py`)
- **14 tests** covering:
  - Database initialization and schema creation
  - CVE storage and retrieval
  - Product/vendor searching with version filtering
  - Search result caching and expiration
  - NVD API integration (mocked)
  - Database statistics

#### Service Scanner Tests (`test_service_scanner.py`)
- **32 tests** covering:
  - Port scanning (open/closed/timeout)
  - Banner grabbing from various services
  - Service identification (SSH, HTTP, FTP, Telnet, etc.)
  - Protocol security analysis
  - Full host scanning workflows
  - Service vulnerability detection

#### Vulnerability Scanner Tests (`test_vulnerability_scanner.py`)
- **41 tests** covering:
  - Device identification (Cisco, Linksys, Netgear, TP-Link)
  - Product/version extraction from banners
  - Device type classification (router/switch/wireless)
  - CVE correlation with service data
  - Risk score calculation
  - Security recommendation generation
  - Severity/CVSS conversions

#### Connection Detector Tests (`test_connection_detector.py`)
- **7 tests** covering:
  - Serial port detection
  - USB device enumeration
  - Network range scanning
  - Connection aggregation

#### Connection Manager Tests (`test_connection_manager.py`)
- **26 tests** covering:
  - SSH connection (success/auth failure/timeout)
  - Serial connection (success/failure/custom baudrate)
  - Command execution (single/multiple)
  - Connection status checking
  - Graceful disconnection

### Integration Tests

#### Vulnerability Workflow Tests (`test_vulnerability_workflow.py`)
- **10 tests** covering:
  - CVE Manager initialization and data flow
  - Service Scanner → Vulnerability Scanner pipeline
  - Device identification with real service data
  - Risk calculation with multiple vulnerabilities
  - Multi-vendor support
  - Error handling for empty results and scan failures

## Test Fixtures

### Common Fixtures (`conftest.py`)
- `temp_db`: Temporary SQLite database for testing
- `mock_cve_data`: Sample CVE records
- `mock_service_results`: Sample port scan results
- `mock_socket`: Mocked network socket for port scanning

## Key Testing Patterns

### Mocking External Dependencies
```python
@patch('requests.get')
@patch('paramiko.SSHClient')
@patch('socket.socket')
```

### Database Testing
- Each test gets a fresh temporary database
- Automatic cleanup after tests
- Tests isolated from production data

### Network Testing
- All network operations are mocked
- No actual network traffic during tests
- Predictable, fast test execution

## Test Metrics

- **Total Tests**: 130
- **Passing**: 130 (100%)
- **Failing**: 0
- **Overall Coverage**: 61%
- **Execution Time**: ~17 seconds

## Known Testing Gaps

1. **GUI Testing**: Main window (0% coverage)
   - Requires PyQt5 testing framework
   - Will be addressed in GUI integration phase

2. **Filesystem Scraper**: (0% coverage)
   - Requires mock filesystem or integration tests
   - To be implemented when scraper is integrated

3. **Service Scanner Edge Cases**: (70% coverage)
   - Some service-specific identification methods
   - SNMP detailed analysis
   - Advanced SSL/TLS certificate validation

## Running Tests in CI/CD

The test suite is designed to run in CI/CD environments:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    pip install -r requirements.txt
    pytest tests/ --cov=src --cov-report=xml
    
- name: Upload coverage
  uses: codecov/codecov-action@v3
```

## Best Practices

1. **Run tests before committing**:
   ```bash
   pytest tests/ -v
   ```

2. **Check coverage for new code**:
   ```bash
   pytest tests/ --cov=src --cov-report=term-missing
   ```

3. **Test individual modules during development**:
   ```bash
   pytest tests/unit/test_<module>.py -v -k test_specific_function
   ```

4. **Use `-x` flag to stop on first failure**:
   ```bash
   pytest tests/ -x
   ```

## Future Testing Plans

### Phase 3
- GUI integration tests using PyQt5 test framework
- End-to-end tests with real device connections (mocked hardware)
- Performance tests for large CVE databases

### Phase 4
- Load testing for concurrent scans
- Security testing (penetration testing)
- Compatibility testing across macOS versions

## Contributing

When adding new features:
1. Write tests first (TDD approach recommended)
2. Ensure new code has >80% coverage
3. Run full test suite before submitting PR
4. Update this document with new test categories

## Troubleshooting

### ResourceWarning: unclosed database
This is a known issue with SQLite and mocking. It doesn't affect test results and can be ignored.

### Import errors
Make sure you're in the project root and have activated the virtual environment:
```bash
source venv/bin/activate
export PYTHONPATH="${PYTHONPATH}:${PWD}"
```

### Qt/PyQt5 errors
If you see Qt-related warnings, they're harmless for unit tests that don't actually use the GUI.
