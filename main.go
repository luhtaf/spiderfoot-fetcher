package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

// Configuration structures
type EPSSData struct {
	CVE  string  `json:"cve"`
	EPSS float64 `json:"epss"`
	Date string  `json:"date"`
}

type EPSSResponse struct {
	Data []EPSSData `json:"data"`
}

type Config struct {
	Database      DatabaseConfig      `yaml:"database"`
	Workers       WorkersConfig       `yaml:"workers"`
	Batch         BatchConfig         `yaml:"batch"`
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch"`
	App           AppConfig           `yaml:"app"`
	SQLQuery      string              `yaml:"sql_query"`
	Stats         StatsConfig         `yaml:"stats"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type WorkersConfig struct {
	Reader  int `yaml:"reader"`
	Parser  int `yaml:"parser"`
	Indexer int `yaml:"indexer"`
}

type BatchConfig struct {
	Size int `yaml:"size"`
}

type ElasticsearchConfig struct {
	URL         string `yaml:"url"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	VerifyCerts bool   `yaml:"verify_certs"`
	Index       string `yaml:"index"`
	CVEIndex    string `yaml:"cve_index"`
	EPSSIndex   string `yaml:"epss_index"`
}

type AppConfig struct {
	Type             string `yaml:"type"`
	Mode             string `yaml:"mode"`
	Version          int    `yaml:"version"`
	TimestampFile    string `yaml:"timestamp_file"`
	FallbackHours    int    `yaml:"fallback_hours"`
	ErrorLog         string `yaml:"error_log"`
	OrganizationData string `yaml:"organization_data"`
}

type StatsConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	File     string        `yaml:"file"`
}

// Data structures for pipeline
type RawRecord struct {
	ID            string
	ScanName      string
	Generated     int64
	Type          string
	Module        string
	Data          string
	Hash          string
	IPAddresses   string
	Vulnerability string
}

type ParsedRecord struct {
	RawRecord
	Timestamp     string `json:"@timestamp"`
	ScanName      string `json:"Scan Name"`
	Updated       string `json:"Updated"`
	Type          string `json:"Type"`
	Module        string `json:"Module"`
	Source        string `json:"Source"`
	FP            int    `json:"F/P"`
	Data          string `json:"Data"`
	Version       int    `json:"version"`
	Case          string `json:"Case,omitempty"`
	Sektor        string `json:"Sektor,omitempty"`
	Organisasi    string `json:"Organisasi,omitempty"`
	Target        string `json:"Target,omitempty"`
	Subsektor     string `json:"Subsektor,omitempty"`
	Vulnerability string `json:"Vulnerability,omitempty"`

	// CVE-specific fields (only for VULNERABILITY_CVE_* types)
	Vuln     string    `json:"Vuln,omitempty"`
	Score    float64   `json:"Score,omitempty"`
	Severity string    `json:"Severity,omitempty"`
	HasCisa  bool      `json:"hasCisa,omitempty"`
	Cisa     *CisaData `json:"cisa,omitempty"`
	HasEpss  bool      `json:"hasEpss,omitempty"`
	Epss     *EpssData `json:"epss,omitempty"`

	// Additional CVE metadata
	LastModified string `json:"lastModified,omitempty"`
	Published    string `json:"published,omitempty"`
	VulnStatus   string `json:"vulnStatus,omitempty"`
}

type CisaData struct {
	CisaActionDue         string `json:"cisaActionDue"`
	CisaExploitAdd        string `json:"cisaExploitAdd"`
	CisaRequiredAction    string `json:"cisaRequiredAction"`
	CisaVulnerabilityName string `json:"cisaVulnerabilityName"`
}

type EpssData struct {
	CVE        string `json:"cve"`
	Epss       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
	Timestamp  string `json:"timestamp"`
}

type CVEData struct {
	Desc         string     `json:"desc"`
	HasCisa      bool       `json:"hasCisa"`
	Cisa         *CisaData  `json:"cisa,omitempty"`
	LastModified string     `json:"lastModified"`
	Published    string     `json:"published"`
	Score        float64    `json:"score"`
	Sev          string     `json:"sev"`
	Source       string     `json:"source"`
	V2           *ScoreData `json:"v2,omitempty"`
	V3           *ScoreData `json:"v3,omitempty"`
	VulnStatus   string     `json:"vulnStatus"`
}

type ScoreData struct {
	Score  float64 `json:"score"`
	Sev    string  `json:"sev"`
	Source string  `json:"source"`
}

// Error logging structure
type ErrorLog struct {
	Timestamp string `json:"timestamp"`
	Stage     string `json:"stage"`
	RecordID  string `json:"record_id"`
	ScanName  string `json:"scan_name"`
	Error     string `json:"error"`
}

// Statistics structures
type StageStats struct {
	RecordsPerSecond    float64 `json:"records_per_second"`
	AvgProcessingTimeMs float64 `json:"avg_processing_time_ms"`
	ActiveWorkers       int     `json:"active_workers"`
	TotalProcessed      int64   `json:"total_processed"`
	QueueDepth          int     `json:"queue_depth,omitempty"`
	ErrorCount          int64   `json:"error_count"`
}

type PipelineStats struct {
	Timestamp string      `json:"timestamp"`
	Reader    *StageStats `json:"reader"`
	Parser    *StageStats `json:"parser"`
	Indexer   *StageStats `json:"indexer"`
	Uptime    string      `json:"uptime"`
}

// Stats collector
type StatsCollector struct {
	enabled      bool
	interval     time.Duration
	file         string
	startTime    time.Time
	mu           sync.RWMutex
	readerStats  *StageStats
	parserStats  *StageStats
	indexerStats *StageStats

	// Metrics channels
	readerMetrics  chan time.Duration
	parserMetrics  chan time.Duration
	indexerMetrics chan time.Duration
	errorChan      chan string
}

func NewStatsCollector(config StatsConfig) *StatsCollector {
	if !config.Enabled {
		return &StatsCollector{enabled: false}
	}

	return &StatsCollector{
		enabled:        true,
		interval:       config.Interval,
		file:           config.File,
		startTime:      time.Now(),
		readerStats:    &StageStats{},
		parserStats:    &StageStats{},
		indexerStats:   &StageStats{},
		readerMetrics:  make(chan time.Duration, 1000),
		parserMetrics:  make(chan time.Duration, 1000),
		indexerMetrics: make(chan time.Duration, 1000),
		errorChan:      make(chan string, 100),
	}
}

func (sc *StatsCollector) Start(ctx context.Context) {
	if !sc.enabled {
		return
	}

	go sc.metricsCollector(ctx)
	go sc.statsWriter(ctx)
}

func (sc *StatsCollector) RecordReader(duration time.Duration) {
	if !sc.enabled {
		return
	}
	select {
	case sc.readerMetrics <- duration:
	default:
		// Channel full, drop metric
	}
}

func (sc *StatsCollector) RecordParser(duration time.Duration) {
	if !sc.enabled {
		return
	}
	select {
	case sc.parserMetrics <- duration:
	default:
		// Channel full, drop metric
	}
}

func (sc *StatsCollector) RecordIndexer(duration time.Duration) {
	if !sc.enabled {
		return
	}
	select {
	case sc.indexerMetrics <- duration:
	default:
		// Channel full, drop metric
	}
}

func (sc *StatsCollector) RecordError(stage string) {
	if !sc.enabled {
		return
	}
	select {
	case sc.errorChan <- stage:
	default:
		// Channel full, drop error
	}
}

func (sc *StatsCollector) metricsCollector(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	readerTimes := make([]time.Duration, 0, 1000)
	parserTimes := make([]time.Duration, 0, 1000)
	indexerTimes := make([]time.Duration, 0, 1000)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Collect metrics and calculate stats
			sc.mu.Lock()

			// Reader stats
			readerTimes = sc.collectMetrics(sc.readerMetrics, readerTimes)
			if len(readerTimes) > 0 {
				sc.readerStats.RecordsPerSecond = float64(len(readerTimes))
				sc.readerStats.AvgProcessingTimeMs = sc.calculateAverage(readerTimes).Seconds() * 1000
				sc.readerStats.TotalProcessed += int64(len(readerTimes))
			}

			// Parser stats
			parserTimes = sc.collectMetrics(sc.parserMetrics, parserTimes)
			if len(parserTimes) > 0 {
				sc.parserStats.RecordsPerSecond = float64(len(parserTimes))
				sc.parserStats.AvgProcessingTimeMs = sc.calculateAverage(parserTimes).Seconds() * 1000
				sc.parserStats.TotalProcessed += int64(len(parserTimes))
			}

			// Indexer stats
			indexerTimes = sc.collectMetrics(sc.indexerMetrics, indexerTimes)
			if len(indexerTimes) > 0 {
				sc.indexerStats.RecordsPerSecond = float64(len(indexerTimes))
				sc.indexerStats.AvgProcessingTimeMs = sc.calculateAverage(indexerTimes).Seconds() * 1000
				sc.indexerStats.TotalProcessed += int64(len(indexerTimes))
			}

			// Error stats
			errorCount := 0
			for {
				select {
				case <-sc.errorChan:
					errorCount++
				default:
					goto errorDone
				}
			}
		errorDone:

			sc.readerStats.ErrorCount += int64(errorCount)

			sc.mu.Unlock()

			// Reset for next second
			readerTimes = readerTimes[:0]
			parserTimes = parserTimes[:0]
			indexerTimes = indexerTimes[:0]
		}
	}
}

func (sc *StatsCollector) collectMetrics(ch chan time.Duration, existing []time.Duration) []time.Duration {
	result := existing[:0]
	for {
		select {
		case duration := <-ch:
			result = append(result, duration)
		default:
			return result
		}
	}
}

func (sc *StatsCollector) calculateAverage(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

func (sc *StatsCollector) statsWriter(ctx context.Context) {
	ticker := time.NewTicker(sc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sc.writeStats()
		}
	}
}

func (sc *StatsCollector) writeStats() {
	sc.mu.RLock()
	stats := PipelineStats{
		Timestamp: time.Now().Format(time.RFC3339),
		Reader:    sc.readerStats,
		Parser:    sc.parserStats,
		Indexer:   sc.indexerStats,
		Uptime:    time.Since(sc.startTime).String(),
	}
	sc.mu.RUnlock()

	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		log.Printf("Error marshaling stats: %v", err)
		return
	}

	file, err := os.OpenFile(sc.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Error opening stats file: %v", err)
		return
	}
	defer file.Close()

	if _, err := file.Write(append(data, '\n')); err != nil {
		log.Printf("Error writing stats: %v", err)
	}
}

// HTTP Client interface for easier mocking
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Elasticsearch HTTP client
type ElasticsearchClient struct {
	httpClient HTTPClient
	baseURL    string
	username   string
	password   string
}

func NewElasticsearchClient(config ElasticsearchConfig) *ElasticsearchClient {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Configure TLS if needed
	if !config.VerifyCerts {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &ElasticsearchClient{
		httpClient: httpClient,
		baseURL:    strings.TrimSuffix(config.URL, "/"),
		username:   config.Username,
		password:   config.Password,
	}
}

// Search performs Elasticsearch search
func (es *ElasticsearchClient) Search(index, query string) (*SearchResponse, error) {
	url := fmt.Sprintf("%s/%s/_search", es.baseURL, index)

	req, err := http.NewRequest("GET", url, strings.NewReader(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if es.username != "" {
		req.SetBasicAuth(es.username, es.password)
	}

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("elasticsearch error %d: %s", resp.StatusCode, string(body))
	}

	var searchResp SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, err
	}

	return &searchResp, nil
}

// SearchRaw performs raw Elasticsearch search and returns generic result
func (es *ElasticsearchClient) SearchRaw(index, query string, target interface{}) error {
	url := fmt.Sprintf("%s/%s/_search", es.baseURL, index)

	req, err := http.NewRequest("GET", url, strings.NewReader(query))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if es.username != "" {
		req.SetBasicAuth(es.username, es.password)
	}

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("elasticsearch error %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// Update performs Elasticsearch update operation
func (es *ElasticsearchClient) Update(index, id string, doc interface{}) error {
	url := fmt.Sprintf("%s/%s/_update/%s", es.baseURL, index, id)

	updateBody := map[string]interface{}{
		"doc": doc,
	}

	data, err := json.Marshal(updateBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if es.username != "" {
		req.SetBasicAuth(es.username, es.password)
	}

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("elasticsearch error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Index performs Elasticsearch index operation
func (es *ElasticsearchClient) Index(index string, doc interface{}) error {
	url := fmt.Sprintf("%s/%s/_doc", es.baseURL, index)

	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if es.username != "" {
		req.SetBasicAuth(es.username, es.password)
	}

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("elasticsearch error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// BulkUpdate performs bulk update operations for better performance
func (es *ElasticsearchClient) BulkUpdate(updates []BulkUpdateItem) error {
	if len(updates) == 0 {
		return nil
	}

	url := fmt.Sprintf("%s/_bulk", es.baseURL)

	// Build bulk request body
	var body strings.Builder
	for _, update := range updates {
		// Update header
		header := map[string]interface{}{
			"update": map[string]interface{}{
				"_index": update.Index,
				"_id":    update.ID,
			},
		}
		headerData, _ := json.Marshal(header)
		body.Write(headerData)
		body.WriteByte('\n')

		// Update document
		docUpdate := map[string]interface{}{
			"doc": update.Doc,
		}
		docData, _ := json.Marshal(docUpdate)
		body.Write(docData)
		body.WriteByte('\n')
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(body.String()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	if es.username != "" {
		req.SetBasicAuth(es.username, es.password)
	}

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("elasticsearch bulk error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to check for individual errors
	var bulkResp BulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
		return fmt.Errorf("failed to decode bulk response: %w", err)
	}

	if bulkResp.Errors {
		// Log individual errors but don't fail the entire batch
		for _, item := range bulkResp.Items {
			for action, result := range item {
				if result.Error != nil {
					log.Printf("Bulk %s error for %s/%s: %v", action, result.Index, result.ID, result.Error)
				}
			}
		}
	}

	return nil
}

// BulkIndex performs bulk index operations for better performance
func (es *ElasticsearchClient) BulkIndex(items []BulkIndexItem) error {
	if len(items) == 0 {
		return nil
	}

	url := fmt.Sprintf("%s/_bulk", es.baseURL)

	// Build bulk request body
	var body strings.Builder
	for _, item := range items {
		// Index header
		header := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": item.Index,
			},
		}
		headerData, _ := json.Marshal(header)
		body.Write(headerData)
		body.WriteByte('\n')

		// Document
		docData, _ := json.Marshal(item.Doc)
		body.Write(docData)
		body.WriteByte('\n')
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(body.String()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	if es.username != "" {
		req.SetBasicAuth(es.username, es.password)
	}

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("elasticsearch bulk index error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to check for individual errors
	var bulkResp BulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
		return fmt.Errorf("failed to decode bulk index response: %w", err)
	}

	if bulkResp.Errors {
		// Log individual errors but don't fail the entire batch
		for _, item := range bulkResp.Items {
			for action, result := range item {
				if result.Error != nil {
					log.Printf("Bulk %s error for %s: %v", action, result.Index, result.Error)
				}
			}
		}
	}

	return nil
}

// SearchResponse structures for Elasticsearch search results
type CVESearchResponse struct {
	Hits struct {
		Hits []struct {
			Source CVEData `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type EPSSSearchResponse struct {
	Hits struct {
		Hits []struct {
			Source EpssData `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// Legacy SearchResponse for backward compatibility
type SearchResponse struct {
	Hits struct {
		Hits []struct {
			Source CVEData `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// Migration search response for updating old records
type MigrationSearchResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Index  string                 `json:"_index"`
			ID     string                 `json:"_id"`
			Source map[string]interface{} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// Bulk update structures
type BulkUpdateItem struct {
	Index string                 `json:"index"`
	ID    string                 `json:"id"`
	Doc   map[string]interface{} `json:"doc"`
}

// Bulk index structures
type BulkIndexItem struct {
	Index string      `json:"index"`
	Doc   interface{} `json:"doc"`
}

type BulkResponse struct {
	Errors bool                          `json:"errors"`
	Items  []map[string]BulkItemResponse `json:"items"`
}

type BulkItemResponse struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Status int                    `json:"status"`
	Error  map[string]interface{} `json:"error,omitempty"`
}

// Pipeline implementation
type Pipeline struct {
	config      Config
	db          *sql.DB
	es          *ElasticsearchClient
	stats       *StatsCollector
	cveCache    sync.Map
	epssCache   sync.Map
	errorLogger *log.Logger

	// Channels for pipeline stages
	rawChan    chan RawRecord
	parsedChan chan ParsedRecord

	// Organization data
	orgData map[string]string

	// Bulk indexing buffer
	bulkBuffer []BulkIndexItem
	bulkMutex  sync.Mutex
}

func NewPipeline(configFile string) (*Pipeline, error) {
	// Load configuration
	config, err := loadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize database
	db, err := sql.Open("sqlite3", config.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Initialize Elasticsearch HTTP client
	es := NewElasticsearchClient(config.Elasticsearch)

	// Initialize error logger
	errorFile, err := os.OpenFile(config.App.ErrorLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open error log: %w", err)
	}

	errorLogger := log.New(errorFile, "", log.LstdFlags)

	// Initialize stats collector
	stats := NewStatsCollector(config.Stats)

	// Load organization data from CSV
	orgData, err := loadOrganizationData(config.App.OrganizationData)
	if err != nil {
		log.Printf("Warning: Failed to load organization data: %v", err)
		orgData = make(map[string]string) // Use empty map as fallback
	}

	return &Pipeline{
		config:      config,
		db:          db,
		es:          es,
		stats:       stats,
		errorLogger: errorLogger,
		orgData:     orgData,
		rawChan:     make(chan RawRecord, config.Batch.Size*2),
		parsedChan:  make(chan ParsedRecord, config.Batch.Size*2),
		bulkBuffer:  make([]BulkIndexItem, 0, 500),
	}, nil
}

func loadConfig(filename string) (Config, error) {
	var config Config
	data, err := os.ReadFile(filename)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(data, &config)
	return config, err
}

func loadOrganizationData(filename string) (map[string]string, error) {
	orgData := make(map[string]string)

	// Skip if filename is empty
	if filename == "" {
		return orgData, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return orgData, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = ';' // Support semicolon delimiter
	records, err := reader.ReadAll()
	if err != nil {
		return orgData, err
	}

	// Skip header row and process data
	for i, record := range records {
		if i == 0 {
			continue // Skip header
		}

		if len(record) >= 2 {
			organisasi := strings.TrimSpace(record[0])
			subsektor := strings.TrimSpace(record[1])
			if organisasi != "" && subsektor != "" {
				orgData[organisasi] = subsektor
			}
		}
	}

	log.Printf("Loaded %d organization mappings from %s", len(orgData), filename)
	return orgData, nil
}

func (p *Pipeline) logError(stage, recordID, scanName, errorMsg string) {
	errorLog := ErrorLog{
		Timestamp: time.Now().Format(time.RFC3339),
		Stage:     stage,
		RecordID:  recordID,
		ScanName:  scanName,
		Error:     errorMsg,
	}

	data, _ := json.Marshal(errorLog)
	p.errorLogger.Println(string(data))
	p.stats.RecordError(stage)
}

// Timestamp management
func (p *Pipeline) getLastTimestamp() (int64, error) {
	data, err := os.ReadFile(p.config.App.TimestampFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Use fallback hours (default 12 hours ago)
			fallbackHours := p.config.App.FallbackHours
			if fallbackHours == 0 {
				fallbackHours = 12 // Default to 12 hours
			}
			fallbackTimestamp := time.Now().Add(-time.Duration(fallbackHours) * time.Hour).Unix()
			// Create file with fallback timestamp
			err = os.WriteFile(p.config.App.TimestampFile, []byte(strconv.FormatInt(fallbackTimestamp, 10)), 0644)
			return fallbackTimestamp, err
		}
		return 0, err
	}

	timestamp, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		// If invalid timestamp, use fallback
		fallbackHours := p.config.App.FallbackHours
		if fallbackHours == 0 {
			fallbackHours = 12
		}
		return time.Now().Add(-time.Duration(fallbackHours) * time.Hour).Unix(), nil
	}

	return timestamp, nil
}

func (p *Pipeline) updateTimestamp(timestamp int64) error {
	return os.WriteFile(p.config.App.TimestampFile, []byte(strconv.FormatInt(timestamp, 10)), 0644)
}

// Simple title case function to replace deprecated strings.Title
func toTitleCase(s string) string {
	if len(s) == 0 {
		return s
	}

	words := strings.Fields(s)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, " ")
}

// Pattern matching for scan name parsing
func parseScanName(scanName string) (case_, sektor, organisasi, target string) {
	// Pattern: {case}_sektor_{sektor}_organisasi_{organisasi}_target_{target}
	re := regexp.MustCompile(`^(.+?)_sektor_(.+?)_organisasi_(.+?)_target_(.+)$`)
	matches := re.FindStringSubmatch(scanName)

	if len(matches) == 5 {
		case_ = toTitleCase(strings.ReplaceAll(matches[1], "_", " "))
		sektor = toTitleCase(strings.ReplaceAll(matches[2], "_", " "))
		organisasi = toTitleCase(strings.ReplaceAll(matches[3], "_", " "))
		target = matches[4]
	}

	return
}

// Stage 1: Reader workers
func (p *Pipeline) readerWorker(ctx context.Context, workerID int, lastTimestamp, nowTimestamp int64) {
	log.Printf("Reader worker %d started", workerID)

	offset := workerID * p.config.Batch.Size

	for {
		select {
		case <-ctx.Done():
			return
		default:
			start := time.Now()

			query := p.config.SQLQuery + " LIMIT ? OFFSET ?"
			rows, err := p.db.Query(query, lastTimestamp, nowTimestamp, p.config.Batch.Size, offset)
			if err != nil {
				p.logError("reader", "", "", fmt.Sprintf("Worker %d query error: %v", workerID, err))
				time.Sleep(time.Second)
				continue
			}

			var records []RawRecord
			for rows.Next() {
				var r RawRecord
				err := rows.Scan(&r.ScanName, &r.Generated, &r.Type, &r.Module, &r.Data, &r.Hash, &r.IPAddresses, &r.Vulnerability)
				if err != nil {
					p.logError("reader", "", "", fmt.Sprintf("Worker %d scan error: %v", workerID, err))
					continue
				}
				r.ID = r.Hash // Use hash as ID
				records = append(records, r)
			}
			rows.Close()

			if len(records) == 0 {
				// No more records for this worker
				log.Printf("Reader worker %d finished - no more records", workerID)
				return
			}

			// Send records to parser stage
			for _, record := range records {
				select {
				case p.rawChan <- record:
				case <-ctx.Done():
					return
				}
			}

			p.stats.RecordReader(time.Since(start))
			offset += p.config.Workers.Reader * p.config.Batch.Size
		}
	}
}

// Stage 2: Parser workers
func (p *Pipeline) parserWorker(ctx context.Context, workerID int) {
	log.Printf("Parser worker %d started", workerID)

	for {
		select {
		case <-ctx.Done():
			return
		case raw := <-p.rawChan:
			start := time.Now()

			parsed, err := p.parseRecord(raw)
			if err != nil {
				p.logError("parser", raw.ID, raw.ScanName, fmt.Sprintf("Worker %d parse error: %v", workerID, err))
				continue
			}

			select {
			case p.parsedChan <- parsed:
			case <-ctx.Done():
				return
			}

			p.stats.RecordParser(time.Since(start))
		}
	}
}

func (p *Pipeline) parseRecord(raw RawRecord) (ParsedRecord, error) {
	parsed := p.buildBaseParsedRecord(raw)

	// Skip empty sources
	if p.isEmptySource(parsed.Source) {
		return parsed, fmt.Errorf("empty source")
	}

	// Parse organization information
	p.parseOrganizationInfo(&parsed, raw.ScanName)

	// Format timestamp for Elasticsearch
	p.formatTimestamp(&parsed, raw.Generated)

	// Apply CVE and EPSS enrichment if applicable
	p.applyEnrichmentIfNeeded(&parsed, raw)

	return parsed, nil
}

func (p *Pipeline) buildBaseParsedRecord(raw RawRecord) ParsedRecord {
	return ParsedRecord{
		RawRecord:     raw,
		ScanName:      raw.ScanName,
		Updated:       time.Unix(raw.Generated, 0).Format("2006-01-02 15:04:05"),
		Type:          raw.Type,
		Module:        raw.Module,
		Source:        raw.IPAddresses,
		FP:            0,
		Data:          raw.Data,
		Version:       p.config.App.Version,
		Vulnerability: raw.Vulnerability,
	}
}

func (p *Pipeline) isEmptySource(source string) bool {
	return source == "" || source == `"`
}

func (p *Pipeline) parseOrganizationInfo(parsed *ParsedRecord, scanName string) {
	case_, sektor, organisasi, target := parseScanName(scanName)
	parsed.Case = case_
	parsed.Sektor = sektor
	parsed.Organisasi = organisasi
	parsed.Target = target

	// Get subsektor from org data
	if subsektor, exists := p.orgData[organisasi]; exists {
		parsed.Subsektor = subsektor
	}
}

func (p *Pipeline) formatTimestamp(parsed *ParsedRecord, generated int64) {
	t := time.Unix(generated, 0)
	parsed.Timestamp = t.Format("2006-01-02T15:04:05.000+07:00")
}

func (p *Pipeline) applyEnrichmentIfNeeded(parsed *ParsedRecord, raw RawRecord) {
	if !p.isCVEVulnerability(raw.Type, raw.Vulnerability) {
		return
	}

	// CVE enrichment
	if err := p.enrichCVE(parsed); err != nil {
		log.Printf("CVE enrichment failed for %s: %v", raw.Vulnerability, err)
		// Continue without enrichment
	}

	// EPSS enrichment
	if err := p.enrichEPSS(parsed); err != nil {
		log.Printf("EPSS enrichment failed for %s: %v", raw.Vulnerability, err)
		// Continue without enrichment
	}
}

func (p *Pipeline) isCVEVulnerability(recordType, vulnerability string) bool {
	return strings.Contains(recordType, "VULNERABILITY") && strings.Contains(vulnerability, "CVE")
}

func (p *Pipeline) enrichCVE(parsed *ParsedRecord) error {
	cveID := parsed.Vulnerability

	// Check cache first
	if cached, exists := p.cveCache.Load(cveID); exists {
		if cveData, ok := cached.(CVEData); ok {
			p.applyCVEData(parsed, cveData)
			return nil
		}
	}

	// Search Elasticsearch for CVE data using consistent approach
	return p.searchAndCacheCVE(cveID, parsed)
}

func (p *Pipeline) searchAndCacheCVE(cveID string, parsed *ParsedRecord) error {
	query := fmt.Sprintf(`{
		"query": {
			"term": {
				"_id": "%s"
			}
		}
	}`, cveID)

	var searchResult CVESearchResponse
	err := p.es.SearchRaw(p.config.Elasticsearch.CVEIndex, query, &searchResult)
	if err != nil {
		return err
	}

	if len(searchResult.Hits.Hits) == 0 {
		// No CVE data found, mark as no CISA
		parsed.HasCisa = false
		return nil
	}

	cveData := searchResult.Hits.Hits[0].Source

	// Cache the result
	p.cveCache.Store(cveID, cveData)

	// Apply CVE data to parsed record
	p.applyCVEData(parsed, cveData)

	return nil
}

func (p *Pipeline) applyCVEData(parsed *ParsedRecord, cve CVEData) {
	parsed.Vuln = parsed.Vulnerability
	parsed.HasCisa = cve.HasCisa

	if cve.HasCisa && cve.Cisa != nil {
		parsed.Cisa = cve.Cisa
	}

	// Prefer v3 score over v2
	if cve.V3 != nil {
		parsed.Score = cve.V3.Score
		parsed.Severity = cve.V3.Sev
	} else if cve.V2 != nil {
		parsed.Score = cve.V2.Score
		parsed.Severity = cve.V2.Sev
	} else {
		parsed.Score = cve.Score
		parsed.Severity = cve.Sev
	}

	parsed.LastModified = cve.LastModified
	parsed.Published = cve.Published
	parsed.VulnStatus = cve.VulnStatus
}

func (p *Pipeline) enrichEPSS(parsed *ParsedRecord) error {
	cveID := parsed.Vulnerability

	// Check cache first
	if cached, exists := p.epssCache.Load(cveID); exists {
		if epssData, ok := cached.(EpssData); ok {
			parsed.HasEpss = true
			parsed.Epss = &epssData
			return nil
		}
	}

	// Search Elasticsearch for EPSS data using consistent approach
	return p.searchAndCacheEPSS(cveID, parsed)
}

func (p *Pipeline) searchAndCacheEPSS(cveID string, parsed *ParsedRecord) error {
	query := fmt.Sprintf(`{
		"query": {
			"term": {
				"_id": "%s"
			}
		}
	}`, cveID)

	var searchResult EPSSSearchResponse
	err := p.es.SearchRaw(p.config.Elasticsearch.EPSSIndex, query, &searchResult)
	if err != nil {
		return err
	}

	if len(searchResult.Hits.Hits) == 0 {
		parsed.HasEpss = false
		return nil
	}

	epssData := searchResult.Hits.Hits[0].Source

	// Cache the result
	p.epssCache.Store(cveID, epssData)

	// Apply EPSS data to parsed record
	parsed.HasEpss = true
	parsed.Epss = &epssData

	return nil
}

// Stage 3: Indexer workers
func (p *Pipeline) indexerWorker(ctx context.Context, workerID int) {
	log.Printf("Indexer worker %d started", workerID)

	// Ticker for periodic bulk flush
	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush remaining buffer before exit
			p.flushBulkBuffer()
			return
		case <-flushTicker.C:
			// Periodic flush
			p.flushBulkBuffer()
		case parsed := <-p.parsedChan:
			start := time.Now()

			if err := p.addToBulkBuffer(parsed); err != nil {
				p.logError("indexer", parsed.ID, parsed.ScanName, fmt.Sprintf("Worker %d buffer error: %v", workerID, err))
				continue
			}

			p.stats.RecordIndexer(time.Since(start))
		}
	}
}

func (p *Pipeline) addToBulkBuffer(record ParsedRecord) error {
	// Generate index name with date
	timestamp := strings.Split(record.Updated, " ")[0]
	indexName := fmt.Sprintf("%s-%s", p.config.Elasticsearch.Index, strings.ReplaceAll(timestamp, "-", "."))

	if p.config.App.Type == "development" {
		log.Printf("Development mode - would index to %s: %s", indexName, record.ScanName)
		return nil
	}

	// Add to bulk buffer
	p.bulkMutex.Lock()
	p.bulkBuffer = append(p.bulkBuffer, BulkIndexItem{
		Index: indexName,
		Doc:   record,
	})

	// Check if buffer is full and needs flushing
	needsFlush := len(p.bulkBuffer) >= 500
	p.bulkMutex.Unlock()

	if needsFlush {
		return p.flushBulkBuffer()
	}

	return nil
}

func (p *Pipeline) flushBulkBuffer() error {
	p.bulkMutex.Lock()
	if len(p.bulkBuffer) == 0 {
		p.bulkMutex.Unlock()
		return nil
	}

	// Copy buffer and reset
	buffer := make([]BulkIndexItem, len(p.bulkBuffer))
	copy(buffer, p.bulkBuffer)
	p.bulkBuffer = p.bulkBuffer[:0]
	p.bulkMutex.Unlock()

	// Perform bulk index
	if err := p.es.BulkIndex(buffer); err != nil {
		log.Printf("Bulk index failed for %d records: %v", len(buffer), err)
		return err
	}

	log.Printf("Bulk indexed %d records", len(buffer))
	return nil
}

// Main pipeline execution
func (p *Pipeline) Run(ctx context.Context) error {
	log.Println("Starting SpiderFoot to Elasticsearch pipeline...")

	// Start stats collector
	p.stats.Start(ctx)

	// Get timestamp range
	lastTimestamp, err := p.getLastTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get last timestamp: %w", err)
	}

	nowTimestamp := time.Now().Unix()
	log.Printf("Processing records from %d to %d", lastTimestamp, nowTimestamp)

	// Start worker goroutines
	var wg sync.WaitGroup

	// Start reader workers
	for i := 0; i < p.config.Workers.Reader; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			p.readerWorker(ctx, workerID, lastTimestamp, nowTimestamp)
		}(i)
	}

	// Start parser workers
	for i := 0; i < p.config.Workers.Parser; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			p.parserWorker(ctx, workerID)
		}(i)
	}

	// Start indexer workers
	for i := 0; i < p.config.Workers.Indexer; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			p.indexerWorker(ctx, workerID)
		}(i)
	}

	// Wait for all workers to complete
	wg.Wait()

	// Final flush of any remaining bulk buffer
	if err := p.flushBulkBuffer(); err != nil {
		log.Printf("Warning: Final bulk flush failed: %v", err)
	}

	// Update timestamp
	if err := p.updateTimestamp(nowTimestamp); err != nil {
		return fmt.Errorf("failed to update timestamp: %w", err)
	}

	log.Println("Pipeline completed successfully")
	return nil
}

// Migration execution for updating old records using scroll API
func (p *Pipeline) RunMigration(ctx context.Context) error {
	log.Println("Starting migration to update old records...")

	// Start stats collector
	p.stats.Start(ctx)

	currentVersion := p.config.App.Version
	batchSize := 5000 // Scroll batch size (will be processed in bulk chunks of 500)
	totalUpdated := 0
	startTime := time.Now()
	var progressBar string

	// Count total records to migrate for progress estimation
	totalRecords, err := p.estimateMigrationJobs(currentVersion)
	if err != nil {
		log.Printf("Warning: Failed to estimate migration jobs: %v", err)
		totalRecords = -1 // Unknown count
	}

	if totalRecords == 0 {
		log.Println("No records to migrate")
		return nil
	} else if totalRecords > 0 {
		log.Printf("Estimated %d records to migrate (processing in batches of %d)", totalRecords, batchSize)
		log.Printf("Estimated time: ~%d-%d minutes", totalRecords/5000, totalRecords/2500) // Rough estimate with bulk 500
	} else {
		log.Println("Starting migration with unknown record count...")
	}

	// Initial scroll search
	scrollID, err := p.initializeScroll(currentVersion, batchSize)
	if err != nil {
		return fmt.Errorf("failed to initialize scroll: %w", err)
	}

	if scrollID == "" {
		log.Println("No records to migrate")
		return nil
	}

	batchNum := 1

	for {
		// Get next batch using scroll
		hits, newScrollID, err := p.getScrollResults(scrollID)
		if err != nil {
			return fmt.Errorf("failed to get scroll results: %w", err)
		}

		if len(hits) == 0 {
			log.Printf("No more records to migrate. Total updated: %d", totalUpdated)
			break
		}

		// Show progress bar (overwrite previous line)
		progressBar := renderProgressBar(totalUpdated, totalRecords, startTime)
		fmt.Printf("\r%s", progressBar)

		// Process records concurrently using errgroup
		batchUpdated, err := p.processMigrationBatch(ctx, hits)
		if err != nil {
			// Clear scroll before returning
			p.clearScroll(scrollID)
			return fmt.Errorf("failed to process migration batch: %w", err)
		}
		totalUpdated += batchUpdated

		scrollID = newScrollID
		batchNum++

		// Check for cancellation
		select {
		case <-ctx.Done():
			// Clear scroll before returning
			p.clearScroll(scrollID)

			// Final progress bar
			progressBar = renderProgressBar(totalUpdated, totalRecords, startTime)
			fmt.Printf("\r%s\n", progressBar)

			elapsed := time.Since(startTime)
			if totalRecords > 0 {
				log.Printf("⚠️  Migration cancelled. Updated %d/%d records (%.1f%% completed).",
					totalUpdated, totalRecords, float64(totalUpdated)/float64(totalRecords)*100)
				log.Printf("⏱️  Time elapsed: %s | Average: %.0f records/second",
					formatDuration(elapsed), float64(totalUpdated)/elapsed.Seconds())
			} else {
				log.Printf("⚠️  Migration cancelled. Updated %d records.", totalUpdated)
				log.Printf("⏱️  Time elapsed: %s", formatDuration(elapsed))
			}
			return ctx.Err()
		default:
		}
	}

	// Clear scroll
	p.clearScroll(scrollID)

	// Final progress bar
	progressBar = renderProgressBar(totalUpdated, totalRecords, startTime)
	fmt.Printf("\r%s\n\n", progressBar)

	// Final summary
	elapsed := time.Since(startTime)
	if totalRecords > 0 {
		log.Printf("✅ Migration completed successfully!")
		log.Printf("📊 Updated %d/%d records to version %d (%.1f%% processed)",
			totalUpdated, totalRecords, currentVersion, float64(totalUpdated)/float64(totalRecords)*100)
		log.Printf("⏱️  Total time: %s | Average: %.0f records/second",
			formatDuration(elapsed), float64(totalUpdated)/elapsed.Seconds())
	} else {
		log.Printf("✅ Migration completed successfully!")
		log.Printf("📊 Updated %d records to version %d", totalUpdated, currentVersion)
		log.Printf("⏱️  Total time: %s", formatDuration(elapsed))
	}
	return nil
}

func (p *Pipeline) prepareMigrationUpdate(hit struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Source map[string]interface{} `json:"_source"`
}) map[string]interface{} {
	// Prepare update document with minimal processing
	updateDoc := map[string]interface{}{
		"version": p.config.App.Version,
	}

	// Fast subsektor lookup
	if organisasi, ok := hit.Source["Organisasi"].(string); ok && organisasi != "" {
		if subsektor, exists := p.orgData[organisasi]; exists {
			updateDoc["Subsektor"] = subsektor
		}
	}

	// Only do enrichment if record has a CVE vulnerability (check Vulnerability or Vuln field)
	var cveID string
	if vulnerability, ok := hit.Source["Vulnerability"].(string); ok && strings.Contains(vulnerability, "CVE") {
		cveID = vulnerability
	} else if vuln, ok := hit.Source["Vuln"].(string); ok && strings.Contains(vuln, "CVE") {
		cveID = vuln
	}

	if cveID != "" {
		// Quick enrichment with minimal overhead
		p.quickEnrichment(cveID, updateDoc)
	}

	return updateDoc
}

func (p *Pipeline) quickEnrichment(vulnerability string, updateDoc map[string]interface{}) {
	// Fetch CVE data (check cache first, then Elasticsearch)
	if err := p.fetchAndApplyCVEData(vulnerability, updateDoc); err != nil {
		// Silently continue if CVE data fetch fails
	}

	// Fetch EPSS data (check cache first, then Elasticsearch)
	if err := p.fetchAndApplyEPSSData(vulnerability, updateDoc); err != nil {
		// Silently continue if EPSS data fetch fails
	}
}

func (p *Pipeline) fetchAndApplyCVEData(vulnerability string, updateDoc map[string]interface{}) error {
	// Check cache first
	if cached, exists := p.cveCache.Load(vulnerability); exists {
		if cveData, ok := cached.(CVEData); ok {
			p.applyCVEDataToUpdate(cveData, updateDoc)
			return nil
		}
	}

	// Fetch from Elasticsearch
	query := fmt.Sprintf(`{
		"query": {
			"term": {
				"_id": "%s"
			}
		}
	}`, vulnerability)

	var searchResult CVESearchResponse
	err := p.es.SearchRaw(p.config.Elasticsearch.CVEIndex, query, &searchResult)
	if err != nil {
		return err
	}

	if len(searchResult.Hits.Hits) == 0 {
		// No CVE data found
		updateDoc["hasCisa"] = false
		return nil
	}

	cveData := searchResult.Hits.Hits[0].Source

	// Cache the result
	p.cveCache.Store(vulnerability, cveData)

	// Apply to update document
	p.applyCVEDataToUpdate(cveData, updateDoc)

	return nil
}

func (p *Pipeline) fetchAndApplyEPSSData(vulnerability string, updateDoc map[string]interface{}) error {
	// Check cache first
	if cached, exists := p.epssCache.Load(vulnerability); exists {
		if epssData, ok := cached.(EpssData); ok {
			updateDoc["hasEpss"] = true
			updateDoc["epss"] = epssData
			return nil
		}
	}

	// Fetch from Elasticsearch
	query := fmt.Sprintf(`{
		"query": {
			"term": {
				"_id": "%s"
			}
		}
	}`, vulnerability)

	var searchResult EPSSSearchResponse
	err := p.es.SearchRaw(p.config.Elasticsearch.EPSSIndex, query, &searchResult)
	if err != nil {
		return err
	}

	if len(searchResult.Hits.Hits) == 0 {
		// No EPSS data found
		updateDoc["hasEpss"] = false
		return nil
	}

	epssData := searchResult.Hits.Hits[0].Source

	// Cache the result
	p.epssCache.Store(vulnerability, epssData)

	// Apply to update document
	updateDoc["hasEpss"] = true
	updateDoc["epss"] = epssData

	return nil
}

func (p *Pipeline) applyCVEDataToUpdate(cve CVEData, updateDoc map[string]interface{}) {
	updateDoc["hasCisa"] = cve.HasCisa

	if cve.HasCisa && cve.Cisa != nil {
		updateDoc["cisa"] = cve.Cisa
	}

	// Prefer v3 score over v2
	if cve.V3 != nil {
		updateDoc["Score"] = cve.V3.Score
		updateDoc["Severity"] = cve.V3.Sev
	} else if cve.V2 != nil {
		updateDoc["Score"] = cve.V2.Score
		updateDoc["Severity"] = cve.V2.Sev
	} else if cve.Score > 0 {
		updateDoc["Score"] = cve.Score
		updateDoc["Severity"] = cve.Sev
	}

	if cve.LastModified != "" {
		updateDoc["lastModified"] = cve.LastModified
	}
	if cve.Published != "" {
		updateDoc["published"] = cve.Published
	}
	if cve.VulnStatus != "" {
		updateDoc["vulnStatus"] = cve.VulnStatus
	}
}

func (p *Pipeline) processMigrationBatch(ctx context.Context, hits []struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Source map[string]interface{} `json:"_source"`
}) (int, error) {
	// Process in chunks for bulk updates (500 records per bulk request)
	bulkSize := 500
	totalUpdated := 0

	for i := 0; i < len(hits); i += bulkSize {
		end := i + bulkSize
		if end > len(hits) {
			end = len(hits)
		}

		chunk := hits[i:end]
		bulkUpdates := make([]BulkUpdateItem, 0, len(chunk))

		// Prepare bulk update items
		for _, hit := range chunk {
			updateDoc := p.prepareMigrationUpdate(hit)
			if len(updateDoc) > 0 {
				bulkUpdates = append(bulkUpdates, BulkUpdateItem{
					Index: hit.Index,
					ID:    hit.ID,
					Doc:   updateDoc,
				})
			}
		}

		if len(bulkUpdates) == 0 {
			continue
		}

		// Perform bulk update
		if err := p.es.BulkUpdate(bulkUpdates); err != nil {
			log.Printf("Bulk update failed for chunk %d-%d: %v", i, end-1, err)
			// Continue with next chunk instead of failing entirely
			continue
		}

		totalUpdated += len(bulkUpdates)
		// Only log every 10th chunk to reduce spam
		if (i/bulkSize)%10 == 0 {
			log.Printf("Progress: %d records updated so far...", totalUpdated)
		}

		// Check for cancellation
		select {
		case <-ctx.Done():
			return totalUpdated, ctx.Err()
		default:
		}
	}

	return totalUpdated, nil
}

// Estimate total migration jobs using count API
func (p *Pipeline) estimateMigrationJobs(currentVersion int) (int, error) {
	query := fmt.Sprintf(`{
		"query": {
			"bool": {
				"should": [
					{"range": {"version": {"lt": %d}}},
					{"bool": {"must_not": {"exists": {"field": "version"}}}}
				]
			}
		}
	}`, currentVersion)

	// Count across all indices matching the pattern
	indexPattern := p.config.Elasticsearch.Index + "*"
	totalCount, err := p.es.Count(indexPattern, query)
	if err != nil {
		return 0, fmt.Errorf("failed to count migration records: %w", err)
	}

	return totalCount, nil
}

// Scroll API methods for handling large result sets
func (p *Pipeline) initializeScroll(currentVersion, batchSize int) (string, error) {
	query := fmt.Sprintf(`{
		"query": {
			"bool": {
				"should": [
					{"range": {"version": {"lt": %d}}},
					{"bool": {"must_not": {"exists": {"field": "version"}}}}
				]
			}
		},
		"size": %d
	}`, currentVersion, batchSize)

	url := fmt.Sprintf("%s/%s/_search?scroll=5m", p.es.baseURL, p.config.Elasticsearch.Index+"*")

	req, err := http.NewRequest("POST", url, strings.NewReader(query))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	if p.es.username != "" {
		req.SetBasicAuth(p.es.username, p.es.password)
	}

	resp, err := p.es.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("elasticsearch error %d: %s", resp.StatusCode, string(body))
	}

	var scrollResult struct {
		ScrollID string `json:"_scroll_id"`
		Hits     struct {
			Hits []struct {
				Index  string                 `json:"_index"`
				ID     string                 `json:"_id"`
				Source map[string]interface{} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&scrollResult); err != nil {
		return "", err
	}

	return scrollResult.ScrollID, nil
}

// Count performs Elasticsearch count operation
func (es *ElasticsearchClient) Count(index, query string) (int, error) {
	url := fmt.Sprintf("%s/%s/_count", es.baseURL, index)

	req, err := http.NewRequest("POST", url, strings.NewReader(query))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	if es.username != "" {
		req.SetBasicAuth(es.username, es.password)
	}

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("elasticsearch count error %d: %s", resp.StatusCode, string(body))
	}

	var countResult struct {
		Count int `json:"count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&countResult); err != nil {
		return 0, err
	}

	return countResult.Count, nil
}

func (p *Pipeline) getScrollResults(scrollID string) ([]struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Source map[string]interface{} `json:"_source"`
}, string, error) {
	scrollBody := fmt.Sprintf(`{
		"scroll": "5m",
		"scroll_id": "%s"
	}`, scrollID)

	url := fmt.Sprintf("%s/_search/scroll", p.es.baseURL)

	req, err := http.NewRequest("POST", url, strings.NewReader(scrollBody))
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Content-Type", "application/json")
	if p.es.username != "" {
		req.SetBasicAuth(p.es.username, p.es.password)
	}

	resp, err := p.es.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("elasticsearch error %d: %s", resp.StatusCode, string(body))
	}

	var scrollResult struct {
		ScrollID string `json:"_scroll_id"`
		Hits     struct {
			Hits []struct {
				Index  string                 `json:"_index"`
				ID     string                 `json:"_id"`
				Source map[string]interface{} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&scrollResult); err != nil {
		return nil, "", err
	}

	return scrollResult.Hits.Hits, scrollResult.ScrollID, nil
}

// Progress bar rendering
func renderProgressBar(current, total int, startTime time.Time) string {
	if total <= 0 {
		return "[████████████████████████████████] ???% | ??? records"
	}

	percentage := float64(current) / float64(total) * 100
	barWidth := 32
	filledWidth := int(float64(barWidth) * percentage / 100)

	// Build progress bar
	var bar strings.Builder
	bar.WriteString("[")
	for i := 0; i < barWidth; i++ {
		if i < filledWidth {
			bar.WriteString("█")
		} else {
			bar.WriteString("░")
		}
	}
	bar.WriteString("]")

	// Calculate ETA
	elapsed := time.Since(startTime)
	var eta string
	if current > 0 && percentage > 0 {
		estimatedTotal := time.Duration(float64(elapsed) / (percentage / 100))
		remaining := estimatedTotal - elapsed
		if remaining > 0 {
			eta = fmt.Sprintf(" | ETA: %s", formatDuration(remaining))
		} else {
			eta = " | ETA: <1m"
		}
	} else {
		eta = " | ETA: calculating..."
	}

	// Calculate speed
	speed := float64(current) / elapsed.Seconds()

	return fmt.Sprintf("%s %.1f%% | %s/%s records | %.0f rec/s%s",
		bar.String(), percentage, formatNumber(current), formatNumber(total), speed, eta)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	} else {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func formatNumber(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	} else if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	} else {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
}

func (p *Pipeline) clearScroll(scrollID string) {
	if scrollID == "" {
		return
	}

	clearBody := fmt.Sprintf(`{
		"scroll_id": ["%s"]
	}`, scrollID)

	url := fmt.Sprintf("%s/_search/scroll", p.es.baseURL)

	req, err := http.NewRequest("DELETE", url, strings.NewReader(clearBody))
	if err != nil {
		log.Printf("Failed to create clear scroll request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if p.es.username != "" {
		req.SetBasicAuth(p.es.username, p.es.password)
	}

	resp, err := p.es.httpClient.Do(req)
	if err != nil {
		log.Printf("Failed to clear scroll: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Failed to clear scroll: %d %s", resp.StatusCode, string(body))
	}
}

func printUsage() {
	fmt.Println("🚀 SpiderFoot to Elasticsearch Pipeline")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  spiderfoot-fetcher [command]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  migrate, migration    Run in migration mode (update existing records)")
	fmt.Println("  pipeline, run         Run in pipeline mode (process new records)")
	fmt.Println("  help, -h, --help      Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  spiderfoot-fetcher              # Default: pipeline mode")
	fmt.Println("  spiderfoot-fetcher migrate      # Migration mode")
	fmt.Println("  spiderfoot-fetcher pipeline     # Explicit pipeline mode")
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Println("  All settings are loaded from config.yaml")
}

func parseCommandArgs() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return ""
}

func validateCommand(command string) string {
	switch command {
	case "migrate", "pipeline":
		log.Printf("🔧 %s mode", command)
		return command
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)
	default:
		log.Printf("❌ Unknown command: %s", command)
		printUsage()
		os.Exit(1)
	}
	return "pipeline" // Default fallback
}

func runWithGracefulShutdown(ctx context.Context, cancel context.CancelFunc, sigChan chan os.Signal, runner func(context.Context) error, mode string) {
	// Run in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- runner(ctx)
	}()

	// Wait for completion or signal
	select {
	case err := <-errChan:
		handleRunCompletion(err, mode)
	case sig := <-sigChan:
		handleSignalShutdown(sig, cancel, errChan, mode)
	}
}

func handleRunCompletion(err error, mode string) {
	if err != nil && err != context.Canceled {
		log.Fatalf("%s failed: %v", strings.Title(mode), err)
	}
	if err == context.Canceled {
		log.Printf("%s cancelled by user", strings.Title(mode))
	} else {
		log.Printf("%s completed successfully", strings.Title(mode))
	}
}

func handleSignalShutdown(sig os.Signal, cancel context.CancelFunc, errChan chan error, mode string) {
	log.Printf("Received signal %v, cancelling %s...", sig, mode)
	cancel()

	// Wait for graceful shutdown or timeout
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			log.Printf("%s cancelled with error: %v", strings.Title(mode), err)
		} else {
			log.Printf("%s cancelled gracefully", strings.Title(mode))
		}
	case <-time.After(30 * time.Second):
		log.Printf("%s cancellation timeout, forcing exit", strings.Title(mode))
	}
}

func main() {
	// Parse and validate command
	command := parseCommandArgs()
	mode := validateCommand(command)

	// Load configuration
	pipeline, err := NewPipeline("config.yaml")
	if err != nil {
		log.Fatalf("Failed to initialize pipeline: %v", err)
	}
	defer pipeline.db.Close()

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Run appropriate mode
	if mode == "migration" {
		log.Println("Running in MIGRATION mode...")
		runWithGracefulShutdown(ctx, cancel, sigChan, pipeline.RunMigration, mode)
	} else {
		log.Println("Running in PIPELINE mode...")
		runWithGracefulShutdown(ctx, cancel, sigChan, pipeline.Run, mode)
	}
}
