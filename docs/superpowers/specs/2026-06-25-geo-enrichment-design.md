# Geo Location Enrichment — Design

**Date:** 2026-06-25
**Status:** Approved (design)
**Scope:** Add geo-location enrichment (latitude/longitude per `Organisasi`) to both the
`pipeline` and `migrate` modes of `spiderfoot-fetcher`, porting the logic from the existing
Python reference script `updatelat.py`.

## Background

`updatelat.py` enriches Elasticsearch documents with a `location` geo_point derived from the
`Organisasi` field. It:

- Aggregates *unique* organizations, geocodes each once via Nominatim, then writes coordinates
  to every document of that organization.
- Builds geocode queries through a large Indonesia-specific ruleset: an `EXACT_ALIASES` table,
  typo replacements, and candidate generators for local governments (pemkot/pemkab/pemprov),
  villages (desa), courts (pengadilan/mahkamah), and embassies (KBRI/KJRI), plus country
  suffixing.
- Rate-limits Nominatim (default 1 request / 2s), retries with backoff on HTTP 429, and caches
  results by query string. It only processes documents that do **not** already have `location`.

The Go tool (`main.go`) already has an analogous enrichment pattern for CVE and EPSS data
(`enrichCVE`, `enrichEPSS`, `quickEnrichment`) using `sync.Map` caches and Elasticsearch lookups.
Geo enrichment will follow the same shape, but keyed on `Organisasi` and backed by a Nominatim
HTTP service rather than an ES index.

## Infrastructure (already provisioned)

Self-hosted Nominatim is deployed to the `kubeth` Kubernetes cluster:

| Item | Value |
|---|---|
| Namespace | `nominatim` |
| Image | `mediagis/nominatim:4.4` (PostgreSQL 14) |
| OSM data | Indonesia extract (geofabrik), persisted on a 60Gi Longhorn PVC at `/var/lib/postgresql/14/main` |
| Service | `nominatim.nominatim.svc:8080` (ClusterIP) |
| Ingress | `http://nominatim.th` (Traefik, `web` entrypoint — same convention as `elk.th`) |

The HTTP API is identical to public Nominatim (`/search?q=...&format=...`), with no strict rate
limit because it is self-hosted. The Go client points at `http://nominatim.th`.

## Approach

**Chosen: Option A — inline per-record enrichment with a shared organization cache.**

Geo enrichment is keyed on `Organisasi` (one organization appears across many documents), so the
core efficiency mechanism is an org → coordinates cache so each unique organization is geocoded
at most once per run. A single `GeoEnricher` component is plugged into the two existing modes,
mirroring how CVE/EPSS enrichment already works. The component is factored cleanly so a future
standalone `geo` mode (mirroring the Python aggregation + `update_by_query` flow) could reuse it,
but that standalone mode is out of scope here.

Rejected alternatives:

- **Separate `geo` command** mirroring Python exactly — does not satisfy the requirement that
  enrichment happen within both `pipeline` and `migrate`.

## Components

### New file: `geo.go`

Isolates all geo logic from `main.go`.

- `GeoPoint{ Lat, Lon float64 }` — marshals to `{"lat":..,"lon":..}` (Elasticsearch `geo_point`).
- `GeoEnricher` struct holding: config, an `*http.Client`, a rate limiter (`sync.Mutex` +
  `nextGeocodeAt time.Time`), a result cache (`sync.Map`, key = original `Organisasi`), and a
  `singleflight.Group` to deduplicate concurrent geocodes of the same organization across worker
  goroutines. Uses `golang.org/x/sync/singleflight` (already present in `go.sum` as an indirect
  dependency; will be promoted to direct).
- Methods:
  - `BuildQueries(org string) []string` — port of `build_geocode_queries` and its helpers.
  - `geocodeOne(query string) (*GeoPoint, error)` — issues `GET {endpoint}/search?q=<query>&format=jsonv2&limit=1`,
    sets the configured `User-Agent`, parses the first hit's `lat`/`lon`, applies rate limiting
    and retry/backoff (429-aware).
  - `EnrichOrganization(org string) (point *GeoPoint, matchedQuery string, err error)` — iterates
    queries from `BuildQueries`, returns the first hit; wrapped by cache + singleflight. A miss
    (no query matched) is stored as a negative cache entry so it is not retried in the same run.

Ported 1:1 from Python (semantics and ordering preserved):

- Data: `exactAliases` (`map[string][]string`), `typoReplacements` (ordered slice of
  `{*regexp.Regexp, replacement string}`).
- Functions: `normalizeSpaces`, `unique`, `applyTypoReplacements`, `cleanOrganizationName`,
  `isOverseasQuery`, `withCountry`, `localGovernmentCandidates`, `villageCandidates`,
  `courtCandidates`, `expandedNameCandidates`, `buildGeocodeQueries`.

### Changes to `main.go`

Add fields to `ParsedRecord` (all `omitempty`):

```go
Location         *GeoPoint `json:"location,omitempty"`
GeoSource        string    `json:"geo_source,omitempty"`
GeoQuery         string    `json:"geo_query,omitempty"`
GeoOriginalQuery string    `json:"geo_original_query,omitempty"`
```

Add `GeoConfig` and wire it into `Config`:

```go
type GeoConfig struct {
    Enabled           bool          `yaml:"enabled"`
    Endpoint          string        `yaml:"endpoint"`
    UserAgent         string        `yaml:"user_agent"`
    MinDelay          time.Duration `yaml:"min_delay"`
    Timeout           time.Duration `yaml:"timeout"`
    MaxRetries        int           `yaml:"max_retries"`
    RateLimit429Sleep time.Duration `yaml:"rate_limit_429_sleep"`
    RetrySleep        time.Duration `yaml:"retry_sleep"`
}
```

`Config` gains `Geo GeoConfig \`yaml:"geo"\``. When the `geo:` section is absent, `Enabled`
defaults to `false`, so existing behavior is unchanged (the feature is opt-in).

`Pipeline` struct gains `geo *GeoEnricher` (nil when disabled). `NewPipeline` constructs it from
`config.Geo` only when `config.Geo.Enabled` is true.

## Data Flow

### Pipeline mode

`parseRecord` → after `parseOrganizationInfo`, call `applyGeoIfNeeded(&parsed)`:

1. Return immediately if `p.geo == nil` or `parsed.Organisasi == ""`.
2. `point, matchedQuery, err := p.geo.EnrichOrganization(parsed.Organisasi)`.
3. On success with a non-nil point: set `parsed.Location = point`,
   `parsed.GeoSource = "Organisasi"`, `parsed.GeoQuery = matchedQuery`,
   `parsed.GeoOriginalQuery = parsed.Organisasi`.
4. On error or miss: log and continue (non-fatal) — the document is still indexed without
   `location`, exactly like the CVE/EPSS enrichment failure path.

New records never already carry `location`, so they are always candidates for enrichment.

### Migrate mode

`prepareMigrationUpdate` → after the subsektor lookup:

1. Skip if `p.geo == nil`.
2. Read `organisasi, _ := hit.Source["Organisasi"].(string)`; skip if empty.
3. **Skip-if-present:** skip if `hit.Source["location"]` already exists.
4. `point, matchedQuery, err := p.geo.EnrichOrganization(organisasi)`; on success set
   `updateDoc["location"]`, `updateDoc["geo_source"] = "Organisasi"`,
   `updateDoc["geo_query"] = matchedQuery`, `updateDoc["geo_original_query"] = organisasi`.
5. On error/miss: leave `updateDoc` untouched for geo fields.

The shared `GeoEnricher` cache spans all scroll batches, so each unique organization is geocoded
once for the whole migration run.

## Configuration

New section in `config.yaml` / `config.yaml.example`:

```yaml
geo:
  enabled: true
  endpoint: "http://nominatim.th"      # Nominatim base URL (self-hosted on kubeth)
  user_agent: "spiderfoot-geo-enricher"
  min_delay: 100ms                     # delay between geocode requests (small for self-hosted)
  timeout: 10s
  max_retries: 8
  rate_limit_429_sleep: 5m             # backoff when Nominatim returns 429
  retry_sleep: 30s                     # backoff on transient errors
```

## Error Handling

- Geocode failures are non-fatal: log and proceed without `location`.
- HTTP 429: hold the shared rate-limit slot and retry up to `max_retries`, with escalating
  backoff (port of `wait_for_geocode_slot` / `postpone_geocode` / `retry_delay_for`).
- Negative cache: organizations with no matching query are cached as a miss and not retried
  within the same run.
- `migrate` skips documents that already have a `location`.

## Testing — `geo_test.go`

- Table-driven `BuildQueries` tests porting representative Python cases: pemkot/pemkab/pemprov,
  desa, pengadilan/mahkamah, KBRI/KJRI, an `EXACT_ALIASES` entry, and a typo-replacement case.
  Assert candidate ordering and country suffixing match the Python behavior.
- `geocodeOne` and `EnrichOrganization` against an `httptest.Server` mock (following the existing
  `HTTPClient` mocking pattern in `main_test.go`):
  - Successful parse of `lat`/`lon`.
  - Cache + singleflight: repeated calls for the same org issue exactly one upstream request.
  - 429 handling: a 429 then success retries and succeeds; rate-limit sleeps are made
    configurable/injectable so tests stay fast.

## Out of Scope

- A standalone `geo` command mirroring the Python aggregation + `update_by_query` flow.
- Cross-run persistence of the geo cache (each run rebuilds its in-memory cache; the
  `skip-if-present` check in migrate already avoids re-geocoding documents that are done).
- Changing the CVE/EPSS enrichment paths.
