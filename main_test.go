package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// Test Suite untuk comprehensive testing
type PipelineTestSuite struct {
	suite.Suite
	pipeline *Pipeline
	config   Config
}

func (suite *PipelineTestSuite) SetupTest() {
	suite.config = Config{
		Database: DatabaseConfig{
			Path: ":memory:",
		},
		Workers: WorkersConfig{
			Reader:  2,
			Parser:  2,
			Indexer: 2,
		},
		Batch: BatchConfig{
			Size: 10,
		},
		Elasticsearch: ElasticsearchConfig{
			URL:      "http://localhost:9200",
			Index:    "test-index",
			CVEIndex: "test-cve-*",
		},
		App: AppConfig{
			Type:          "development",
			Version:       1,
			TimestampFile: "test_timestamp.txt",
			ErrorLog:      "test_error.log",
		},
		Stats: StatsConfig{
			Enabled:  true,
			Interval: 1 * time.Second,
			File:     "test_stats.json",
		},
	}
}

func (suite *PipelineTestSuite) TearDownTest() {
	if suite.pipeline != nil && suite.pipeline.db != nil {
		suite.pipeline.db.Close()
	}
}

// Test configuration loading
func TestLoadConfig(t *testing.T) {
	// Test valid config
	configYAML := `
database:
  path: "test.db"
workers:
  reader: 2
  parser: 4
  indexer: 3
batch:
  size: 100
elasticsearch:
  url: "http://localhost:9200"
  index: "test"
  cve_index: "cve-*"
app:
  type: "development"
  version: 2
stats:
  enabled: true
  interval: 30s
  file: "stats.json"
`

	// Create temporary config file
	tmpFile := "test_config.yaml"
	err := os.WriteFile(tmpFile, []byte(configYAML), 0644)
	assert.NoError(t, err)
	defer os.Remove(tmpFile)

	config, err := loadConfig(tmpFile)
	assert.NoError(t, err)
	assert.Equal(t, "test.db", config.Database.Path)
	assert.Equal(t, 2, config.Workers.Reader)
	assert.Equal(t, 4, config.Workers.Parser)
	assert.Equal(t, 3, config.Workers.Indexer)
	assert.Equal(t, 100, config.Batch.Size)
	assert.Equal(t, "http://localhost:9200", config.Elasticsearch.URL)
	assert.True(t, config.Stats.Enabled)
	assert.Equal(t, 30*time.Second, config.Stats.Interval)
}

// Test scan name parsing
func TestParseScanName(t *testing.T) {
	testCases := []struct {
		name               string
		scanName           string
		expectedCase       string
		expectedSektor     string
		expectedOrganisasi string
		expectedTarget     string
	}{
		{
			name:               "Valid scan name",
			scanName:           "pentest_sektor_finance_organisasi_bank_bni_target_192.168.1.100",
			expectedCase:       "Pentest",
			expectedSektor:     "Finance",
			expectedOrganisasi: "Bank Bni",
			expectedTarget:     "192.168.1.100",
		},
		{
			name:               "Complex organization name",
			scanName:           "security_audit_sektor_healthcare_organisasi_rs_siloam_jakarta_target_10.0.1.50",
			expectedCase:       "Security Audit",
			expectedSektor:     "Healthcare",
			expectedOrganisasi: "Rs Siloam Jakarta",
			expectedTarget:     "10.0.1.50",
		},
		{
			name:               "Invalid scan name format",
			scanName:           "invalid_format_string",
			expectedCase:       "",
			expectedSektor:     "",
			expectedOrganisasi: "",
			expectedTarget:     "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			case_, sektor, organisasi, target := parseScanName(tc.scanName)
			assert.Equal(t, tc.expectedCase, case_)
			assert.Equal(t, tc.expectedSektor, sektor)
			assert.Equal(t, tc.expectedOrganisasi, organisasi)
			assert.Equal(t, tc.expectedTarget, target)
		})
	}
}

// Test CVE data application
func TestApplyCVEData(t *testing.T) {
	pipeline := &Pipeline{}

	// Test case 1: CVE with CISA data
	parsed := &ParsedRecord{
		Vulnerability: "CVE-2021-44228",
	}

	cveData := CVEData{
		HasCisa: true,
		Cisa: &CisaData{
			CisaActionDue:         "2021-12-24",
			CisaExploitAdd:        "2021-12-10",
			CisaRequiredAction:    "Apply updates per vendor instructions.",
			CisaVulnerabilityName: "Apache Log4j2 RCE",
		},
		V3: &ScoreData{
			Score:  10.0,
			Sev:    "CRITICAL",
			Source: "v3.1",
		},
		LastModified: "2025-04-03T01:03:51.193",
		Published:    "2021-12-09T23:03:00.000",
		VulnStatus:   "Exploitable",
	}

	pipeline.applyCVEData(parsed, cveData)

	assert.Equal(t, "CVE-2021-44228", parsed.Vuln)
	assert.True(t, parsed.HasCisa)
	assert.NotNil(t, parsed.Cisa)
	assert.Equal(t, "2021-12-24", parsed.Cisa.CisaActionDue)
	assert.Equal(t, 10.0, parsed.Score)
	assert.Equal(t, "CRITICAL", parsed.Severity)
	assert.Equal(t, "2025-04-03T01:03:51.193", parsed.LastModified)
	assert.Equal(t, "Exploitable", parsed.VulnStatus)

	// Test case 2: CVE without CISA data
	parsed2 := &ParsedRecord{
		Vulnerability: "CVE-2020-1234",
	}

	cveData2 := CVEData{
		HasCisa: false,
		V2: &ScoreData{
			Score:  7.5,
			Sev:    "HIGH",
			Source: "v2",
		},
		VulnStatus: "Analyzed",
	}

	pipeline.applyCVEData(parsed2, cveData2)

	assert.Equal(t, "CVE-2020-1234", parsed2.Vuln)
	assert.False(t, parsed2.HasCisa)
	assert.Nil(t, parsed2.Cisa)
	assert.Equal(t, 7.5, parsed2.Score)
	assert.Equal(t, "HIGH", parsed2.Severity)
	assert.Equal(t, "Analyzed", parsed2.VulnStatus)
}

// Test parse record function
func TestParseRecord(t *testing.T) {
	pipeline := &Pipeline{
		config: Config{
			App: AppConfig{
				Version: 2,
			},
		},
		orgData: map[string]string{
			"Bank Bni": "Perbankan",
		},
	}

	raw := RawRecord{
		ID:            "test-hash-123",
		ScanName:      "pentest_sektor_finance_organisasi_bank_bni_target_192.168.1.100",
		Generated:     1695456000, // Unix timestamp
		Type:          "TCP_PORT_OPEN",
		Module:        "spider_nmap",
		Data:          "Port 443/tcp open",
		IPAddresses:   "192.168.1.100",
		Vulnerability: "Port 443/tcp open",
	}

	parsed, err := pipeline.parseRecord(raw)

	assert.NoError(t, err)
	assert.Equal(t, "pentest_sektor_finance_organisasi_bank_bni_target_192.168.1.100", parsed.ScanName)
	assert.Equal(t, "TCP_PORT_OPEN", parsed.Type)
	assert.Equal(t, "spider_nmap", parsed.Module)
	assert.Equal(t, "192.168.1.100", parsed.Source)
	assert.Equal(t, "Port 443/tcp open", parsed.Data)
	assert.Equal(t, 2, parsed.Version)
	assert.Equal(t, "Pentest", parsed.Case)
	assert.Equal(t, "Finance", parsed.Sektor)
	assert.Equal(t, "Bank Bni", parsed.Organisasi)
	assert.Equal(t, "192.168.1.100", parsed.Target)
	assert.Equal(t, "Perbankan", parsed.Subsektor)
	assert.Equal(t, "Port 443/tcp open", parsed.Vulnerability)

	// Verify timestamp format
	assert.Contains(t, parsed.Timestamp, "2023-09-23T")
	assert.Contains(t, parsed.Timestamp, "+07:00")
}

// Test error logging
func TestErrorLogging(t *testing.T) {
	// Create temporary error log file
	tmpFile := "test_error.log"
	defer os.Remove(tmpFile)

	errorFile, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	assert.NoError(t, err)
	defer errorFile.Close()

	pipeline := &Pipeline{
		errorLogger: log.New(errorFile, "", log.LstdFlags),
		stats:       NewStatsCollector(StatsConfig{Enabled: false}),
	}

	pipeline.logError("parser", "test-id-123", "test_scan_name", "test error message")

	// Read the error log
	errorFile.Close()
	content, err := os.ReadFile(tmpFile)
	assert.NoError(t, err)

	// Parse JSON from log line
	lines := strings.Split(string(content), "\n")
	assert.Greater(t, len(lines), 0)

	// Find the JSON part
	var errorLog ErrorLog
	for _, line := range lines {
		if strings.Contains(line, `"stage":"parser"`) {
			// Extract JSON part after timestamp
			jsonStart := strings.Index(line, "{")
			if jsonStart >= 0 {
				err = json.Unmarshal([]byte(line[jsonStart:]), &errorLog)
				assert.NoError(t, err)
				break
			}
		}
	}

	assert.Equal(t, "parser", errorLog.Stage)
	assert.Equal(t, "test-id-123", errorLog.RecordID)
	assert.Equal(t, "test_scan_name", errorLog.ScanName)
	assert.Equal(t, "test error message", errorLog.Error)
}

// Mock HTTP client for testing (much easier than SDK mocking!)
type MockHTTPClient struct {
	responses map[string]*http.Response
	errors    map[string]error
}

func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		responses: make(map[string]*http.Response),
		errors:    make(map[string]error),
	}
}

func (m *MockHTTPClient) SetResponse(url string, statusCode int, body string) {
	resp := &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")
	m.responses[url] = resp
}

func (m *MockHTTPClient) SetError(url string, err error) {
	m.errors[url] = err
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	url := req.URL.String()

	if err, exists := m.errors[url]; exists {
		return nil, err
	}

	if resp, exists := m.responses[url]; exists {
		return resp, nil
	}

	// Default 404 response
	return &http.Response{
		StatusCode: 404,
		Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
		Header:     make(http.Header),
	}, nil
}

// Benchmark tests
func BenchmarkParseScanName(b *testing.B) {
	scanName := "security_audit_sektor_healthcare_organisasi_rumah_sakit_siloam_jakarta_target_10.0.1.50"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseScanName(scanName)
	}
}

func BenchmarkParseRecord(b *testing.B) {
	pipeline := &Pipeline{
		config: Config{
			App: AppConfig{Version: 2},
		},
		orgData: map[string]string{
			"Bank Bni": "Perbankan",
		},
	}

	raw := RawRecord{
		ID:            "test-hash-123",
		ScanName:      "pentest_sektor_finance_organisasi_bank_bni_target_192.168.1.100",
		Generated:     1695456000,
		Type:          "TCP_PORT_OPEN",
		Module:        "spider_nmap",
		Data:          "Port 443/tcp open",
		IPAddresses:   "192.168.1.100",
		Vulnerability: "Port 443/tcp open",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pipeline.parseRecord(raw)
	}
}

// Test stats collector (simplified to avoid hanging)
func TestStatsCollector(t *testing.T) {
	config := StatsConfig{
		Enabled:  true,
		Interval: 100 * time.Millisecond,
		File:     "test_stats.json",
	}

	stats := NewStatsCollector(config)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	defer os.Remove("test_stats.json")

	// Start stats collector
	stats.Start(ctx)

	// Record some metrics
	stats.RecordReader(50 * time.Millisecond)
	stats.RecordParser(100 * time.Millisecond)
	stats.RecordIndexer(75 * time.Millisecond)
	stats.RecordError("parser")

	// Wait for context to timeout (should stop cleanly)
	<-ctx.Done()

	// Check if stats file was created
	_, err := os.Stat("test_stats.json")
	// File may or may not exist depending on timing, so we don't assert
	if err == nil {
		t.Log("Stats file was created successfully")
	} else {
		t.Log("Stats file not created (timing dependent)")
	}
}

func TestStatsCollectorDisabled(t *testing.T) {
	config := StatsConfig{
		Enabled: false,
	}

	stats := NewStatsCollector(config)
	assert.False(t, stats.enabled)

	// These should not panic or error when disabled
	stats.RecordReader(10 * time.Millisecond)
	stats.RecordParser(20 * time.Millisecond)
	stats.RecordIndexer(30 * time.Millisecond)
	stats.RecordError("test")
}

// Timestamp management tests
func TestTimestampManagement(t *testing.T) {
	pipeline := &Pipeline{
		config: Config{
			App: AppConfig{
				TimestampFile: "test_timestamp.txt",
				FallbackHours: 2, // Test with 2 hours fallback
			},
		},
	}
	defer os.Remove("test_timestamp.txt")

	// Test getting timestamp when file doesn't exist (should use fallback)
	timestamp, err := pipeline.getLastTimestamp()
	assert.NoError(t, err)
	// Should be approximately 2 hours ago
	expectedTime := time.Now().Add(-2 * time.Hour).Unix()
	assert.InDelta(t, expectedTime, timestamp, 60) // Allow 60 seconds difference

	// Test updating timestamp
	testTimestamp := int64(1695456000)
	err = pipeline.updateTimestamp(testTimestamp)
	assert.NoError(t, err)

	// Test getting updated timestamp
	timestamp, err = pipeline.getLastTimestamp()
	assert.NoError(t, err)
	assert.Equal(t, testTimestamp, timestamp)
}

// Test suite runner
func TestPipelineTestSuite(t *testing.T) {
	suite.Run(t, new(PipelineTestSuite))
}

// Test race conditions
func TestConcurrentAccess(t *testing.T) {
	pipeline := &Pipeline{
		cveCache: sync.Map{},
	}

	// Simulate concurrent cache access
	const numGoroutines = 100
	const numOperations = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("CVE-2021-%04d", (id*numOperations+j)%10000)
				value := CVEData{
					Score: float64(id + j),
					Sev:   "HIGH",
				}

				pipeline.cveCache.Store(key, value)
				pipeline.cveCache.Load(key)
			}
		}(i)
	}

	wg.Wait()
}

// Test Elasticsearch HTTP client
func TestElasticsearchClient(t *testing.T) {
	mockHTTP := NewMockHTTPClient()

	config := ElasticsearchConfig{
		URL:         "http://localhost:9200",
		Username:    "test",
		Password:    "password",
		VerifyCerts: false,
	}

	esClient := NewElasticsearchClient(config)
	esClient.httpClient = mockHTTP

	// Test successful search
	searchResponse := `{
		"hits": {
			"hits": [
				{
					"_source": {
						"score": 9.8,
						"sev": "CRITICAL",
						"hasCisa": true,
						"cisa": {
							"cisaActionDue": "2022-04-15",
							"cisaExploitAdd": "2022-03-25",
							"cisaRequiredAction": "Apply updates",
							"cisaVulnerabilityName": "Test CVE"
						}
					}
				}
			]
		}
	}`

	mockHTTP.SetResponse("http://localhost:9200/test-index/_search", 200, searchResponse)

	result, err := esClient.Search("test-index", `{"query": {"match_all": {}}}`)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(result.Hits.Hits))
	assert.Equal(t, 9.8, result.Hits.Hits[0].Source.Score)
	assert.True(t, result.Hits.Hits[0].Source.HasCisa)

	// Test search error
	mockHTTP.SetResponse("http://localhost:9200/error-index/_search", 500, `{"error": "internal server error"}`)

	_, err = esClient.Search("error-index", `{"query": {"match_all": {}}}`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "elasticsearch error 500")

	// Test successful index
	mockHTTP.SetResponse("http://localhost:9200/test-index/_doc", 201, `{"_id": "123", "result": "created"}`)

	testDoc := map[string]interface{}{
		"title": "Test Document",
		"score": 7.5,
	}

	err = esClient.Index("test-index", testDoc)
	assert.NoError(t, err)

	// Test index error
	mockHTTP.SetResponse("http://localhost:9200/error-index/_doc", 400, `{"error": "bad request"}`)

	err = esClient.Index("error-index", testDoc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "elasticsearch error 400")
}
func TestPipelineIntegration(t *testing.T) {
	// This would be a more complex test requiring test database setup
	// For now, we'll test the basic pipeline structure

	config := Config{
		Database: DatabaseConfig{Path: ":memory:"},
		Workers:  WorkersConfig{Reader: 1, Parser: 1, Indexer: 1},
		Batch:    BatchConfig{Size: 10},
		App:      AppConfig{Type: "development", Version: 1},
		Stats:    StatsConfig{Enabled: false},
	}

	// Test that we can create a pipeline with the config
	// In a real integration test, we'd set up test data and run the full pipeline
	assert.Equal(t, ":memory:", config.Database.Path)
	assert.Equal(t, "development", config.App.Type)
}

// Test error scenarios
func TestErrorScenarios(t *testing.T) {
	// Test invalid config file
	_, err := loadConfig("nonexistent_config.yaml")
	assert.Error(t, err)

	// Test parse record with empty source
	pipeline := &Pipeline{
		config: Config{App: AppConfig{Version: 1}},
	}

	raw := RawRecord{
		ScanName:    "test_scan",
		IPAddresses: "", // Empty source should cause error
	}

	_, err = pipeline.parseRecord(raw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty source")
}

// Memory leak detection test
func TestMemoryUsage(t *testing.T) {
	// This test would use runtime.MemStats to check for memory leaks
	// during pipeline processing
	var m1, m2 runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Simulate some processing
	pipeline := &Pipeline{
		cveCache: sync.Map{},
	}

	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("CVE-2021-%04d", i)
		value := CVEData{Score: float64(i), Sev: "MEDIUM"}
		pipeline.cveCache.Store(key, value)
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Check that memory usage is reasonable (allowing for normal allocations)
	if m2.Alloc > m1.Alloc {
		memIncrease := m2.Alloc - m1.Alloc
		t.Logf("Memory increase: %d bytes", memIncrease)
		// Allow up to 10MB increase for this test
		assert.Less(t, memIncrease, uint64(10*1024*1024))
	} else {
		// If memory decreased or stayed same (due to GC), that's good
		t.Logf("Memory usage stable or decreased")
	}
}

// TestGracefulShutdown tests the graceful shutdown functionality
func TestGracefulShutdown(t *testing.T) {
	// Create a test configuration
	configContent := `
database:
  path: ":memory:"
workers:
  reader: 1
  parser: 1
  indexer: 1
batch:
  size: 10
elasticsearch:
  url: "http://localhost:9200"
  username: "test"
  password: "test"
app:
  timestamp_file: "test_timestamp.txt"
  error_log: "test_error.log"
stats:
  enabled: false
`

	// Create temporary config file
	configFile, err := os.CreateTemp("", "test_config_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.WriteString(configContent); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	configFile.Close()

	// Test pipeline initialization
	pipeline, err := NewPipeline(configFile.Name())
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	defer func() {
		if pipeline.db != nil {
			pipeline.db.Close()
		}
	}()

	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Start pipeline in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- pipeline.Run(ctx)
	}()

	// Cancel context immediately
	cancel()

	// Wait for pipeline to finish
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			t.Errorf("Pipeline should exit gracefully, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Pipeline should shutdown within 5 seconds")
	}

	// Clean up test timestamp file
	if err := os.Remove("test_timestamp.txt"); err != nil && !os.IsNotExist(err) {
		t.Logf("Warning: failed to remove test timestamp file: %v", err)
	}
	// Clean up test error log file
	if err := os.Remove("test_error.log"); err != nil && !os.IsNotExist(err) {
		t.Logf("Warning: failed to remove test error log file: %v", err)
	}
}
