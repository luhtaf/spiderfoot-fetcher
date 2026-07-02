package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// GeoPoint is an Elasticsearch geo_point ({"lat":..,"lon":..}).
type GeoPoint struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// geoResult is the cached outcome of geocoding one organization. Point is nil
// when no candidate query matched (negative cache entry).
type geoResult struct {
	Point *GeoPoint
	Query string
}

// GeoEnricher resolves an Organisasi name to coordinates via a Nominatim
// HTTP service. It ports the query-building logic from updatelat.py and adds
// per-organization caching, single-flight de-duplication, rate limiting and
// 429-aware retry/backoff.
type GeoEnricher struct {
	config     GeoConfig
	httpClient HTTPClient
	endpoint   string

	cache sync.Map // key: original Organisasi string -> geoResult
	group singleflight.Group

	rateMu      sync.Mutex
	nextGeocode time.Time

	// sleepFn is overridable in tests to avoid real backoff waits.
	sleepFn func(time.Duration)
	nowFn   func() time.Time
}

// NewGeoEnricher builds an enricher from config, applying sane defaults for any
// unset values. Returns nil when geo enrichment is disabled.
func NewGeoEnricher(config GeoConfig) *GeoEnricher {
	if !config.Enabled {
		return nil
	}

	if config.UserAgent == "" {
		config.UserAgent = "spiderfoot-geo-enricher"
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 8
	}
	if config.MinDelay < 0 {
		config.MinDelay = 0
	}
	if config.RateLimit429Sleep <= 0 {
		config.RateLimit429Sleep = 5 * time.Minute
	}
	if config.RetrySleep <= 0 {
		config.RetrySleep = 30 * time.Second
	}

	return &GeoEnricher{
		config:     config,
		endpoint:   strings.TrimSuffix(config.Endpoint, "/"),
		httpClient: &http.Client{Timeout: config.Timeout},
		sleepFn:    time.Sleep,
		nowFn:      time.Now,
	}
}

// EnrichOrganization geocodes an organization, returning the matched point, the
// query that matched, and an error (only for hard geocode failures). A nil
// point with nil error means no candidate query matched. Results are cached per
// organization for the lifetime of the enricher.
func (g *GeoEnricher) EnrichOrganization(organisasi string) (*GeoPoint, string, error) {
	organisasi = normalizeSpaces(organisasi)
	if organisasi == "" {
		return nil, "", nil
	}

	if cached, ok := g.cache.Load(organisasi); ok {
		res := cached.(geoResult)
		return res.Point, res.Query, nil
	}

	v, err, _ := g.group.Do(organisasi, func() (interface{}, error) {
		// Re-check the cache: a concurrent caller may have populated it.
		if cached, ok := g.cache.Load(organisasi); ok {
			return cached.(geoResult), nil
		}

		point, query, err := g.geocodeOrganization(organisasi)
		if err != nil {
			return geoResult{}, err
		}

		res := geoResult{Point: point, Query: query}
		g.cache.Store(organisasi, res)
		return res, nil
	})
	if err != nil {
		return nil, "", err
	}

	res := v.(geoResult)
	return res.Point, res.Query, nil
}

// geocodeOrganization tries each candidate query in order and returns the first
// hit.
func (g *GeoEnricher) geocodeOrganization(organisasi string) (*GeoPoint, string, error) {
	queries := buildGeocodeQueries(organisasi)

	for _, query := range queries {
		point, err := g.geocodeOne(query)
		if err != nil {
			return nil, "", err
		}
		if point != nil {
			return point, query, nil
		}
	}

	return nil, "", nil
}

// nominatimResult mirrors the relevant fields of a Nominatim /search result.
type nominatimResult struct {
	Lat string `json:"lat"`
	Lon string `json:"lon"`
}

// geocodeOne issues a single Nominatim search, applying rate limiting and
// 429-aware retry/backoff. A nil point with nil error means "no match".
func (g *GeoEnricher) geocodeOne(searchText string) (*GeoPoint, error) {
	var lastErr error

	for attempt := 1; attempt <= g.config.MaxRetries; attempt++ {
		g.waitForGeocodeSlot()

		point, rateLimited, err := g.doGeocodeRequest(searchText)
		if err == nil {
			return point, nil
		}

		lastErr = err
		if attempt >= g.config.MaxRetries {
			break
		}

		delay := g.retryDelay(rateLimited, attempt)
		g.postponeGeocode(delay)
		g.sleepFn(delay)
	}

	return nil, fmt.Errorf("geocode failed for %q: %w", searchText, lastErr)
}

// doGeocodeRequest performs the HTTP call and parses the first hit. The bool
// return reports whether the failure was a rate-limit (HTTP 429).
func (g *GeoEnricher) doGeocodeRequest(searchText string) (*GeoPoint, bool, error) {
	endpoint := fmt.Sprintf("%s/search?q=%s&format=jsonv2&limit=1",
		g.endpoint, url.QueryEscape(searchText))

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", g.config.UserAgent)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, true, fmt.Errorf("nominatim 429 rate limited")
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("nominatim error %d: %s", resp.StatusCode, string(body))
	}

	var results []nominatimResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, false, err
	}

	if len(results) == 0 {
		return nil, false, nil
	}

	lat, err := strconv.ParseFloat(results[0].Lat, 64)
	if err != nil {
		return nil, false, fmt.Errorf("invalid lat %q: %w", results[0].Lat, err)
	}
	lon, err := strconv.ParseFloat(results[0].Lon, 64)
	if err != nil {
		return nil, false, fmt.Errorf("invalid lon %q: %w", results[0].Lon, err)
	}

	return &GeoPoint{Lat: lat, Lon: lon}, false, nil
}

// waitForGeocodeSlot enforces the configured minimum delay between requests
// across all goroutines (port of wait_for_geocode_slot).
func (g *GeoEnricher) waitForGeocodeSlot() {
	if g.config.MinDelay <= 0 {
		return
	}

	g.rateMu.Lock()
	now := g.nowFn()
	sleepFor := g.nextGeocode.Sub(now)
	if sleepFor > 0 {
		g.nextGeocode = now.Add(sleepFor + g.config.MinDelay)
		g.rateMu.Unlock()
		g.sleepFn(sleepFor)
		return
	}
	g.nextGeocode = now.Add(g.config.MinDelay)
	g.rateMu.Unlock()
}

// postponeGeocode holds the shared rate-limit slot for at least the given
// duration (port of postpone_geocode), used after errors/429s.
func (g *GeoEnricher) postponeGeocode(seconds time.Duration) {
	if seconds <= 0 {
		return
	}

	g.rateMu.Lock()
	target := g.nowFn().Add(seconds)
	if target.After(g.nextGeocode) {
		g.nextGeocode = target
	}
	g.rateMu.Unlock()
}

func (g *GeoEnricher) retryDelay(rateLimited bool, attempt int) time.Duration {
	if rateLimited {
		return time.Duration(attempt) * g.config.RateLimit429Sleep
	}
	return time.Duration(attempt) * g.config.RetrySleep
}

// ---------------------------------------------------------------------------
// Query building — ported 1:1 from updatelat.py
// ---------------------------------------------------------------------------

var multiSpaceRe = regexp.MustCompile(`\s+`)

func normalizeSpaces(value string) string {
	return strings.TrimSpace(multiSpaceRe.ReplaceAllString(value, " "))
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{})

	for _, value := range values {
		value = normalizeSpaces(value)
		if value == "" {
			continue
		}
		lower := strings.ToLower(value)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		result = append(result, value)
	}

	return result
}

type typoReplacement struct {
	re   *regexp.Regexp
	repl string
}

// typoReplacements ports TYPO_REPLACEMENTS. Patterns are compiled
// case-insensitive to match the Python re.IGNORECASE behavior.
var typoReplacements = []typoReplacement{
	{regexp.MustCompile(`(?i)\bBandar Sri Begawan\b`), "Bandar Seri Begawan"},
	{regexp.MustCompile(`(?i)\bIntellijen\b`), "Intelijen"},
	{regexp.MustCompile(`(?i)\bKejaksanaan\b`), "Kejaksaan"},
	{regexp.MustCompile(`(?i)\bKementarian\b`), "Kementerian"},
	{regexp.MustCompile(`(?i)\bKementrian\b`), "Kementerian"},
	{regexp.MustCompile(`(?i)\bKemeterian\b`), "Kementerian"},
	{regexp.MustCompile(`(?i)\bPermasyarakatan\b`), "Pemasyarakatan"},
	{regexp.MustCompile(`(?i)\bKependudukaan\b`), "Kependudukan"},
	{regexp.MustCompile(`(?i)\bbadan\b`), "Badan"},
	{regexp.MustCompile(`(?i)\bRi\b`), "Republik Indonesia"},
}

func applyTypoReplacements(value string) string {
	value = normalizeSpaces(value)
	for _, tr := range typoReplacements {
		value = tr.re.ReplaceAllString(value, tr.repl)
	}
	return normalizeSpaces(value)
}

func cleanOrganizationName(value string) string {
	value = normalizeSpaces(value)
	value = strings.ReplaceAll(value, "/badan", "/Badan")
	value = strings.ReplaceAll(value, "&", "Dan")
	return applyTypoReplacements(value)
}

var overseasHints = []string{
	"australia",
	"brunei",
	"japan",
	"malaysia",
	"south korea",
	"united states",
	"usa",
}

func isOverseasQuery(value string) bool {
	lower := strings.ToLower(value)
	for _, country := range overseasHints {
		if strings.Contains(lower, country) {
			return true
		}
	}
	return false
}

func withCountry(value string) string {
	if strings.Contains(strings.ToLower(value), "indonesia") || isOverseasQuery(value) {
		return value
	}
	return value + ", Indonesia"
}

func localGovernmentCandidates(cleanName string) []string {
	lower := strings.ToLower(cleanName)

	switch {
	case strings.HasPrefix(lower, "pemkot "):
		city := strings.TrimSpace(cleanName[len("pemkot "):])
		return []string{"Kota " + city, "Pemerintah Kota " + city, city}
	case strings.HasPrefix(lower, "pemkab "):
		regency := strings.TrimSpace(cleanName[len("pemkab "):])
		return []string{"Kabupaten " + regency, "Pemerintah Kabupaten " + regency, regency}
	case strings.HasPrefix(lower, "pemprov "):
		province := strings.TrimSpace(cleanName[len("pemprov "):])
		return []string{"Provinsi " + province, "Pemerintah Provinsi " + province, province}
	case strings.HasPrefix(lower, "pemerintah kabupaten "):
		regency := strings.TrimSpace(cleanName[len("pemerintah kabupaten "):])
		return []string{"Kabupaten " + regency, "Pemerintah Kabupaten " + regency, regency}
	case strings.HasPrefix(lower, "pemerintah kota "):
		city := strings.TrimSpace(cleanName[len("pemerintah kota "):])
		return []string{"Kota " + city, "Pemerintah Kota " + city, city}
	case strings.HasPrefix(lower, "pemerintah provinsi "):
		province := strings.TrimSpace(cleanName[len("pemerintah provinsi "):])
		return []string{"Provinsi " + province, "Pemerintah Provinsi " + province, province}
	case strings.HasPrefix(lower, "kabupaten "):
		regency := strings.TrimSpace(cleanName[len("kabupaten "):])
		return []string{cleanName, regency}
	case strings.HasPrefix(lower, "kota "):
		city := strings.TrimSpace(cleanName[len("kota "):])
		return []string{cleanName, city}
	case strings.HasPrefix(lower, "provinsi "):
		province := strings.TrimSpace(cleanName[len("provinsi "):])
		return []string{cleanName, province}
	}

	return nil
}

func villageCandidates(cleanName string) []string {
	lower := strings.ToLower(cleanName)
	if !strings.HasPrefix(lower, "desa ") {
		return nil
	}
	village := strings.TrimSpace(cleanName[len("desa "):])
	return []string{cleanName, village}
}

var courtPrefixes = []string{
	"mahkamah syariyah ",
	"mahkamah syar'iyah ",
	"pengadilan agama ",
	"pengadilan negeri ",
	"pengadilan tinggi agama ",
}

func courtCandidates(cleanName string) []string {
	lower := strings.ToLower(cleanName)
	for _, prefix := range courtPrefixes {
		if strings.HasPrefix(lower, prefix) {
			place := strings.TrimSpace(cleanName[len(prefix):])
			return []string{cleanName, place}
		}
	}
	return nil
}

func expandedNameCandidates(cleanName string) []string {
	lower := strings.ToLower(cleanName)
	var candidates []string

	if strings.HasPrefix(lower, "kbri ") {
		city := strings.TrimSpace(cleanName[len("kbri "):])
		candidates = append(candidates,
			"Kedutaan Besar Republik Indonesia "+city,
			"Embassy of Indonesia "+city,
		)
	}

	if strings.HasPrefix(lower, "kjri ") {
		city := strings.TrimSpace(cleanName[len("kjri "):])
		candidates = append(candidates,
			"Konsulat Jenderal Republik Indonesia "+city,
			"Consulate General of Indonesia "+city,
		)
	}

	candidates = append(candidates, cleanName)
	return candidates
}

func buildGeocodeQueries(organisasi string) []string {
	original := normalizeSpaces(organisasi)
	cleanName := cleanOrganizationName(original)

	var base []string
	base = append(base, exactAliases[original]...)
	base = append(base, exactAliases[cleanName]...)
	base = append(base, localGovernmentCandidates(cleanName)...)
	base = append(base, villageCandidates(cleanName)...)
	base = append(base, courtCandidates(cleanName)...)
	base = append(base, expandedNameCandidates(cleanName)...)

	base = uniqueStrings(base)

	overseasName := false
	for _, candidate := range base {
		if isOverseasQuery(candidate) {
			overseasName = true
			break
		}
	}

	cleanLower := strings.ToLower(cleanName)
	localName := len(localGovernmentCandidates(cleanName)) > 0 ||
		len(villageCandidates(cleanName)) > 0 ||
		len(courtCandidates(cleanName)) > 0 ||
		overseasName ||
		strings.HasPrefix(cleanLower, "kbri ") ||
		strings.HasPrefix(cleanLower, "kjri ")

	var queries []string
	for _, candidate := range base {
		queries = append(queries, withCountry(candidate))
		lowerCandidate := strings.ToLower(candidate)
		if !localName && !strings.Contains(candidate, ",") && !strings.Contains(lowerCandidate, "jakarta") {
			queries = append(queries, candidate+", Jakarta, Indonesia")
		}
	}

	return uniqueStrings(queries)
}
