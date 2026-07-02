package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestGeoConfigParsesDurations(t *testing.T) {
	data := []byte(`
geo:
  enabled: true
  endpoint: "http://nominatim.th"
  min_delay: 100ms
  timeout: 10s
  max_retries: 8
  rate_limit_429_sleep: 5m
  retry_sleep: 30s
`)

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	g := config.Geo
	if !g.Enabled {
		t.Error("expected Enabled=true")
	}
	if g.MinDelay != 100*time.Millisecond {
		t.Errorf("MinDelay = %v, want 100ms", g.MinDelay)
	}
	if g.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", g.Timeout)
	}
	if g.RateLimit429Sleep != 5*time.Minute {
		t.Errorf("RateLimit429Sleep = %v, want 5m", g.RateLimit429Sleep)
	}
	if g.RetrySleep != 30*time.Second {
		t.Errorf("RetrySleep = %v, want 30s", g.RetrySleep)
	}
}

func TestBuildGeocodeQueries(t *testing.T) {
	tests := []struct {
		name string
		org  string
		want []string
	}{
		{
			name: "pemkot generates kota candidates",
			org:  "Pemkot Bandung",
			want: []string{
				"Kota Bandung, Indonesia",
				"Pemerintah Kota Bandung, Indonesia",
				"Bandung, Indonesia",
				"Pemkot Bandung, Indonesia",
			},
		},
		{
			name: "pemkab generates kabupaten candidates",
			org:  "Pemkab Sleman",
			want: []string{
				"Kabupaten Sleman, Indonesia",
				"Pemerintah Kabupaten Sleman, Indonesia",
				"Sleman, Indonesia",
				"Pemkab Sleman, Indonesia",
			},
		},
		{
			name: "village alias takes priority and adds plain candidates",
			org:  "Desa Kutawaringin",
			want: []string{
				"Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
				"Desa Kutawaringin, Indonesia",
				"Kutawaringin, Indonesia",
			},
		},
		{
			name: "court prefix without alias",
			org:  "Pengadilan Negeri Sleman",
			want: []string{
				"Pengadilan Negeri Sleman, Indonesia",
				"Sleman, Indonesia",
			},
		},
		{
			name: "typo replacement and jakarta fallback for non-local name",
			org:  "Kementrian Keuangan",
			want: []string{
				"Kementerian Keuangan, Indonesia",
				"Kementerian Keuangan, Jakarta, Indonesia",
			},
		},
		{
			name: "kbri expands to embassy candidates",
			org:  "Kbri Tokyo",
			want: []string{
				"Kedutaan Besar Republik Indonesia Tokyo",
				"Embassy of Indonesia Tokyo, Japan",
				"Tokyo, Japan",
				"Embassy of Indonesia Tokyo",
				"Kbri Tokyo, Indonesia",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildGeocodeQueries(tt.org)
			if !equalStrings(got, tt.want) {
				t.Errorf("buildGeocodeQueries(%q)\n got: %#v\nwant: %#v", tt.org, got, tt.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// countingClient is an HTTPClient that counts calls and delegates response
// construction to a handler, so each call gets a fresh body.
type countingClient struct {
	mu      sync.Mutex
	calls   int
	handler func(callNum int, req *http.Request) (int, string)
}

func (c *countingClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.calls++
	n := c.calls
	c.mu.Unlock()

	status, body := c.handler(n, req)
	resp := &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
	return resp, nil
}

func (c *countingClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// newTestEnricher builds a GeoEnricher with an injected client and no real sleeps.
func newTestEnricher(client HTTPClient) *GeoEnricher {
	return &GeoEnricher{
		config: GeoConfig{
			Enabled:           true,
			Endpoint:          "http://nominatim.test",
			UserAgent:         "test",
			MinDelay:          0,
			MaxRetries:        3,
			RateLimit429Sleep: time.Millisecond,
			RetrySleep:        time.Millisecond,
		},
		endpoint:   "http://nominatim.test",
		httpClient: client,
		sleepFn:    func(time.Duration) {},
		nowFn:      time.Now,
	}
}

const jakartaHit = `[{"lat":"-6.1751","lon":"106.8650"}]`

func TestGeocodeOneSuccess(t *testing.T) {
	client := &countingClient{handler: func(_ int, _ *http.Request) (int, string) {
		return 200, jakartaHit
	}}
	g := newTestEnricher(client)

	point, err := g.geocodeOne("Jakarta, Indonesia")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if point == nil {
		t.Fatal("expected a point, got nil")
	}
	if point.Lat != -6.1751 || point.Lon != 106.8650 {
		t.Errorf("unexpected coordinates: %+v", point)
	}
}

func TestEnrichOrganizationCachesPerOrg(t *testing.T) {
	client := &countingClient{handler: func(_ int, _ *http.Request) (int, string) {
		return 200, jakartaHit
	}}
	g := newTestEnricher(client)

	for i := 0; i < 3; i++ {
		point, query, err := g.EnrichOrganization("Badan Standardisasi Nasional")
		if err != nil {
			t.Fatalf("call %d error: %v", i, err)
		}
		if point == nil {
			t.Fatalf("call %d: expected a point", i)
		}
		if query == "" {
			t.Fatalf("call %d: expected a matched query", i)
		}
	}

	// First candidate matches immediately, so exactly one upstream request total.
	if got := client.count(); got != 1 {
		t.Errorf("expected 1 upstream request (cached afterwards), got %d", got)
	}
}

func TestEnrichOrganizationConcurrentSingleFlight(t *testing.T) {
	client := &countingClient{handler: func(_ int, _ *http.Request) (int, string) {
		return 200, jakartaHit
	}}
	g := newTestEnricher(client)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = g.EnrichOrganization("Bappenas")
		}()
	}
	wg.Wait()

	if got := client.count(); got != 1 {
		t.Errorf("expected single-flight to collapse to 1 request, got %d", got)
	}
}

func TestGeocodeOneRetriesAfter429(t *testing.T) {
	client := &countingClient{handler: func(callNum int, _ *http.Request) (int, string) {
		if callNum == 1 {
			return 429, `rate limited`
		}
		return 200, jakartaHit
	}}
	g := newTestEnricher(client)

	point, err := g.geocodeOne("Jakarta, Indonesia")
	if err != nil {
		t.Fatalf("unexpected error after retry: %v", err)
	}
	if point == nil {
		t.Fatal("expected a point after 429 retry")
	}
	if client.count() != 2 {
		t.Errorf("expected 2 requests (429 then success), got %d", client.count())
	}
}

func TestEnrichOrganizationNoMatch(t *testing.T) {
	client := &countingClient{handler: func(_ int, _ *http.Request) (int, string) {
		return 200, `[]`
	}}
	g := newTestEnricher(client)

	point, query, err := g.EnrichOrganization("Organisasi Yang Tidak Ada")
	if err != nil {
		t.Fatalf("no-match should not error, got: %v", err)
	}
	if point != nil || query != "" {
		t.Errorf("expected no match, got point=%v query=%q", point, query)
	}

	callsAfterFirst := client.count()
	// Second call should be served from the negative cache, no new requests.
	_, _, _ = g.EnrichOrganization("Organisasi Yang Tidak Ada")
	if client.count() != callsAfterFirst {
		t.Errorf("negative cache miss: expected no new requests, went from %d to %d",
			callsAfterFirst, client.count())
	}
}
