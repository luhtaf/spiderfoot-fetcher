package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
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
}

type AppConfig struct {
	Type          string `yaml:"type"`
	Version       int    `yaml:"version"`
	TimestampFile string `yaml:"timestamp_file"`
	FallbackHours int    `yaml:"fallback_hours"`
	ErrorLog      string `yaml:"error_log"`
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

// SearchResponse structure for Elasticsearch search results
type SearchResponse struct {
	Hits struct {
		Hits []struct {
			Source CVEData `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// Pipeline implementation
type Pipeline struct {
	config      Config
	db          *sql.DB
	es          *ElasticsearchClient
	stats       *StatsCollector
	cveCache    sync.Map
	errorLogger *log.Logger

	// Channels for pipeline stages
	rawChan    chan RawRecord
	parsedChan chan ParsedRecord

	// Organization data
	orgData map[string]string
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

	// Load organization data (simplified, should load from CSV)
	orgData := make(map[string]string)

	return &Pipeline{
		config:      config,
		db:          db,
		es:          es,
		stats:       stats,
		errorLogger: errorLogger,
		orgData:     orgData,
		rawChan:     make(chan RawRecord, config.Batch.Size*2),
		parsedChan:  make(chan ParsedRecord, config.Batch.Size*2),
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
	parsed := ParsedRecord{
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

	// Skip empty sources
	if parsed.Source == "" || parsed.Source == `"` {
		return parsed, fmt.Errorf("empty source")
	}

	// Parse scan name for organization info
	case_, sektor, organisasi, target := parseScanName(raw.ScanName)
	parsed.Case = case_
	parsed.Sektor = sektor
	parsed.Organisasi = organisasi
	parsed.Target = target

	// Get subsektor from org data
	if subsektor, exists := p.orgData[organisasi]; exists {
		parsed.Subsektor = subsektor
	}

	// Format timestamp for Elasticsearch
	t := time.Unix(raw.Generated, 0)
	parsed.Timestamp = t.Format("2006-01-02T15:04:05.000+07:00")

	// CVE enrichment for VULNERABILITY_CVE_* types
	if strings.Contains(raw.Type, "VULNERABILITY_CVE") && strings.Contains(raw.Vulnerability, "CVE") {
		if err := p.enrichCVE(&parsed); err != nil {
			log.Printf("CVE enrichment failed for %s: %v", raw.Vulnerability, err)
			// Continue without enrichment
		}
	}

	return parsed, nil
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

	// Search Elasticsearch for CVE data
	query := fmt.Sprintf(`{
		"query": {
			"term": {
				"_id": "%s"
			}
		}
	}`, cveID)

	searchResult, err := p.es.Search(p.config.Elasticsearch.CVEIndex, query)
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

// Stage 3: Indexer workers
func (p *Pipeline) indexerWorker(ctx context.Context, workerID int) {
	log.Printf("Indexer worker %d started", workerID)

	for {
		select {
		case <-ctx.Done():
			return
		case parsed := <-p.parsedChan:
			start := time.Now()

			if err := p.indexRecord(parsed); err != nil {
				p.logError("indexer", parsed.ID, parsed.ScanName, fmt.Sprintf("Worker %d index error: %v", workerID, err))
				continue
			}

			p.stats.RecordIndexer(time.Since(start))
		}
	}
}

func (p *Pipeline) indexRecord(record ParsedRecord) error {
	// Generate index name with date
	timestamp := strings.Split(record.Updated, " ")[0]
	indexName := fmt.Sprintf("%s-%s", p.config.Elasticsearch.Index, strings.ReplaceAll(timestamp, "-", "."))

	if p.config.App.Type == "development" {
		log.Printf("Development mode - would index to %s: %s", indexName, record.ScanName)
		return nil
	}

	// Index to Elasticsearch using HTTP client
	if err := p.es.Index(indexName, record); err != nil {
		return err
	}

	log.Printf("Indexed to %s: %s", indexName, record.ScanName)
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

	// Update timestamp
	if err := p.updateTimestamp(nowTimestamp); err != nil {
		return fmt.Errorf("failed to update timestamp: %w", err)
	}

	log.Println("Pipeline completed successfully")
	return nil
}

func main() {
	// Load configuration
	pipeline, err := NewPipeline("config.yaml")
	if err != nil {
		log.Fatalf("Failed to initialize pipeline: %v", err)
	}
	defer pipeline.db.Close()

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Run pipeline in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- pipeline.Run(ctx)
	}()

	// Wait for completion or signal
	select {
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Pipeline failed: %v", err)
		}
		log.Println("Pipeline completed successfully")
	case sig := <-sigChan:
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)
		cancel()

		// Wait for pipeline to finish gracefully or timeout
		select {
		case err := <-errChan:
			if err != nil && err != context.Canceled {
				log.Printf("Pipeline shutdown with error: %v", err)
			} else {
				log.Println("Pipeline shutdown gracefully")
			}
		case <-time.After(30 * time.Second):
			log.Println("Shutdown timeout exceeded, forcing exit")
		}
	}
}
