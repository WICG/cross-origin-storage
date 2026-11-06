-- HTTP Archive BigQuery query for the Public Hash List.
--
-- Identifies web resources (scripts, CSS, fonts, WASM) whose SHA-256 body hash
-- appears across ≥100 independent sites in the HTTP Archive monthly crawl.
-- The ≥100-sites threshold is the k-anonymity privacy gate: a resource that
-- widespread cannot serve as a cross-site identifier.
--
-- A site is the registrable domain (eTLD+1) of the embedding page, computed
-- with the full Public Suffix List (ICANN and private sections). So
-- city1.example.com and city2.example.com count as the single site
-- example.com, while alice.github.io and bob.github.io count as two sites.
-- Counting hostnames would let a resource found only on many subdomains of one
-- site (say $city.$vulnerable-group.com) pass the gate while still identifying
-- that site.
--
-- Traffic-weighted score: each hash is scored by SUM(100000 / min_rank) across
-- sites, where min_rank is the CrUX popularity bucket of the site's most
-- popular embedding page (1 000 = top 1K sites → 100 pts; 1 000 000 = top 1M →
-- 0.1 pt). This lifts hashes carried by high-traffic pages to the top of the
-- list.
--
-- This is a copy for reference. The query the HTTP Archive runs lives in its
-- Dataform repository, where `ctx.ref()` stands in for the table names below:
--   https://github.com/HTTPArchive/dataform/blob/main/definitions/output/performance/public_hash_list.js
-- It runs monthly once the crawl completes, against httparchive.crawl.requests.
-- The private PSL rules come from httparchive.urls.public_suffix_list, which
-- the same Airflow DAG keeps in sync with publicsuffix.org. Results are
-- published directly by the HTTP Archive, fetched by http-archive.js:
--   https://cdn.httparchive.org/v1/static/reports/public_hash_list.csv

-- Private section of the Public Suffix List. BigQuery's NET.PUBLIC_SUFFIX()
-- only applies the ICANN section, which would merge all *.github.io pages
-- into one site.
WITH private_suffixes AS (
  SELECT suffix, is_wildcard
  FROM httparchive.urls.public_suffix_list
  WHERE is_private AND NOT is_exception
),

request_pages AS (
  SELECT
    SAFE.STRING(payload._body_hash) AS body_hash, -- SHA-256 hash from WPT payload
    type,
    LOWER(NET.HOST(page)) AS page_host,            -- host of the embedding page
    MIN(rank) AS min_rank,                         -- the most popular page rank bucket
    ANY_VALUE(url) AS sample_url
  FROM httparchive.crawl.requests
  WHERE
    date = DATE_TRUNC(CURRENT_DATE(), MONTH)
    AND SAFE.STRING(payload._body_hash) IS NOT NULL
    AND type IN ('script', 'css', 'font', 'wasm')
    AND SAFE.STRING(summary.method) = 'GET'
    AND NET.HOST(page) IS NOT NULL
  GROUP BY
    body_hash,
    type,
    page_host
),

-- Every suffix of every page host, for example a.example.co.uk yields
-- uk, co.uk, example.co.uk, and a.example.co.uk.
host_suffixes AS (
  SELECT
    host,
    ARRAY_LENGTH(SPLIT(host, '.')) AS host_labels,
    num_labels,
    ARRAY_TO_STRING(
      ARRAY(
        SELECT label
        FROM UNNEST(SPLIT(host, '.')) AS label WITH OFFSET AS i
        WHERE i >= ARRAY_LENGTH(SPLIT(host, '.')) - num_labels
        ORDER BY i
      ),
      '.'
    ) AS suffix
  FROM (SELECT DISTINCT page_host AS host FROM request_pages)
  CROSS JOIN UNNEST(GENERATE_ARRAY(1, ARRAY_LENGTH(SPLIT(host, '.')))) AS num_labels
),

-- Length in labels of each host's longest matching public suffix, ICANN or
-- private. A wildcard rule *.x makes the suffix one label longer than x
-- public. 0 means no rule matched (IP addresses, unknown TLDs).
public_suffix_lengths AS (
  SELECT
    s.host,
    ANY_VALUE(s.host_labels) AS host_labels,
    MAX(
      CASE
        WHEN p.is_wildcard THEN s.num_labels + 1
        WHEN p.suffix IS NOT NULL THEN s.num_labels
        WHEN s.suffix = NET.PUBLIC_SUFFIX(s.host) THEN s.num_labels
        ELSE 0
      END
    ) AS suffix_labels
  FROM host_suffixes AS s
  LEFT JOIN private_suffixes AS p
  ON s.suffix = p.suffix
  GROUP BY s.host
),

-- The site is the public suffix plus one label. Hosts without a public
-- suffix, or that are a public suffix themselves, are their own site.
host_sites AS (
  SELECT
    s.host,
    s.suffix AS site
  FROM host_suffixes AS s
  INNER JOIN public_suffix_lengths AS l
  ON s.host = l.host
  WHERE
    s.num_labels = IF(
      l.suffix_labels = 0,
      l.host_labels,
      LEAST(l.suffix_labels + 1, l.host_labels)
    )
),

request_sites AS (
  SELECT
    r.body_hash,
    r.type,
    h.site,
    MIN(r.min_rank) AS min_rank,
    ANY_VALUE(r.sample_url) AS sample_url
  FROM request_pages AS r
  INNER JOIN host_sites AS h
  ON r.page_host = h.host
  GROUP BY
    r.body_hash,
    r.type,
    h.site
),

hash_popularity AS (
  SELECT
    body_hash,
    type,
    COUNT(*) AS num_sites,
    SUM(100000.0 / min_rank) AS traffic_weighted_score, -- top 1K website gets 100 points; top 1M gets 0.1 point
    ANY_VALUE(sample_url) AS sample_url
  FROM request_sites
  GROUP BY
    body_hash,
    type
)

SELECT
  body_hash,
  type,
  num_sites,
  traffic_weighted_score,
  sample_url
FROM hash_popularity
WHERE
  num_sites >= 100 -- privacy threshold (k-anonymity gate)
ORDER BY
  traffic_weighted_score DESC
