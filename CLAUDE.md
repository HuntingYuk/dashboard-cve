# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-page Streamlit dashboard ("CVE Intelligence Dashboard" for BSSN) that reads pre-indexed CVE
documents from an Elasticsearch 8.x index named `list-cve` and renders filters, metrics, Plotly charts,
and a detail table. It does not ingest or write data; something else populates the index.

There are only two source files:

- `app.py` — the whole UI. Runs top-to-bottom on every Streamlit rerun.
- `es_service.py` — ES client construction, the shared bool-query builder, and the two fetch functions.

There is no test suite. CI only does syntax/lint/security checks.

## Commands

```bash
# Local setup
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then fill ES_URL or ES_CLOUD_ID, ES_USERNAME, ES_PASSWORD

# Run (dev, foreground)
streamlit run app.py --server.port 8501

# Run detached on a VM (writes streamlit.log)
./run.sh

# Exactly what CI runs for Python
python -m compileall -q .
ruff check --select E9,F63,F7,F82 app.py es_service.py

# Docker
docker build -t dashboard-cve .
docker run --rm -p 8501:8501 --env-file .env dashboard-cve
# health endpoint used by the Docker HEALTHCHECK: http://127.0.0.1:8501/_stcore/health
```

## Configuration

`es_service.py` loads `.env` from the project root (path resolved relative to the file, not the cwd).
Variables: `ES_URL` or `ES_CLOUD_ID` (one is required, cloud id wins if both set), `ES_USERNAME`,
`ES_PASSWORD`. URL mode disables TLS cert verification on purpose (self-signed on-prem ES).
The client version is asserted to be the 8.x series at runtime, and `requirements.txt` pins
`elasticsearch>=8.17.0,<9` to match.

Streamlit theme lives in `.streamlit/config.toml`; additional dark-theme CSS overrides are inlined
in `app.py` via `st.markdown(..., unsafe_allow_html=True)`. Plotly charts use `template="plotly_dark"`
with `paper_bgcolor='#262730'` to match.

## Data flow and how filters work

Every rerun of `app.py` does, in order:

1. Seed `st.session_state` from `FILTER_DEFAULTS`, then apply any `pending_filter_update` queued by
   a chart click on the previous run.
2. Render sidebar widgets. Every filter widget is bound to its session-state key via `key=` and
   takes no `value=`/`default=`/`index=` argument (Streamlit warns when both are given).
3. Build one `active_filters` dict. It is passed as `**kwargs` to `load_data`, `load_stats`, and
   `load_priority` (all `@st.cache_data(ttl=600)`), so it is also the cache key. Timezone is a
   separate argument to the loaders that convert timestamps.
4. `load_today_metrics()` (`ttl=300`) feeds the "New today / Modified today" header metrics; their
   "View" buttons switch the filters to today's date via an `on_click` callback.
5. Render metrics, sparklines, chart tabs, the Priority Watchlist (`fetch_priority_cves`, ranked
   server-side by KEV / CVSS / EPSS), and the detail table.

`fetch_cve_data`, `fetch_summary_stats`, and `fetch_priority_cves` in `es_service.py` all take
`**filters` and call `_build_bool_query(**filters)`, the single source of truth for filter semantics.

**To add a new filter**: add a default to `FILTER_DEFAULTS`, a sidebar widget with that key, an entry
in `active_filters`, a parameter on `_build_bool_query`, and the clause itself. Nothing else needs to
change.

**Chart click-to-filter**: Streamlit forbids writing to a widget's session-state key after that
widget has rendered, so chart handlers never write filters directly. `clicked_point_index()` renders
a Plotly chart with `on_select="rerun"` under a key that includes `chart_nonce`; on a click the
handler calls `request_filter_update(...)`, which stores the change in `pending_filter_update`,
bumps the nonce (so the chart re-mounts with an empty selection and does not re-fire), and reruns.
The change is applied in step 1 of the next run.

Score filtering uses `v3.score` (float) with a fallback to `score` (integer-mapped) for v2-only
CVEs, and is only added when the slider is narrower than 0–10. The Priority Watchlist sorts on the
same effective score via a Painless script.

## Testing UI interactions headlessly

Plotly bar charts put a transparent `rect.nsewdrag` overlay over the plot area, so Playwright clicks
on bar paths time out. Dispatch synthetic `mousemove` then `mousedown/mouseup/click` MouseEvents at
the bar's bounding-box centre on `document.elementFromPoint(x, y)` instead. Tabs are
`div[data-testid="stTab"]` in Streamlit 1.63. Pie slices could not be clicked this way in testing;
verify pie click-to-filter manually.

Date semantics: "Observation Mode" (All Time / Specific Date / Date Range) picks a date filter, and
"CVE Status Type" picks which field it applies to, `published` or `lastModified`. That same field is
also used for the year filter and for every `date_histogram` aggregation. The histogram interval for
the severity sparklines is chosen in `fetch_summary_stats` based on the span of the date range.

## Elasticsearch document shape

Fields the code depends on in the `list-cve` index (keyword sub-fields are used for terms/aggs):

`id`, `desc`, `sev` / `sev.keyword` (LOW|MEDIUM|HIGH|CRITICAL), `score` (CVSS base), `published`,
`lastModified`, `vulnStatus.keyword`, `vendors.keyword`, `products.keyword` (both are arrays),
`hasCisa` (bool, CISA KEV), `cisa.*` (KEV due date, name), `epss`, `percentile`, `source.keyword`
(CVSS version), `v2.*` / `v3.*` (per-version score objects), and
`original.weaknesses.description.value.keyword` (CWE).

Facts verified against the production index (Sept 2026) that shape the query code:

- `source.keyword` values are `v3.1`, `v3.0`, `v2` (see `CVSS_VERSION_SOURCES`).
- `score` and `v2.score` are mapped as `long` (decimals truncated at index time); `v3.score` is a
  float. The `score_histogram` aggregation therefore has integer buckets.
- About 26k docs (mostly `Rejected`, `Deferred`, `Received`) have no `score`, `sev`, or `epss`.
  They are included unless the user narrows the score/EPSS sliders.
- `vulnStatus` has seven values, including `Undergoing Analysis`.
- `published` spans 1988 to the current year; `lastModified` only goes back to late 2023.
- `top_weaknesses` excludes `NVD-CWE-noinfo` / `NVD-CWE-Other` placeholders.
- `vendors` and `products` are arrays; the tables join them with commas for display.

## Known quirks to be aware of before editing

- `app.py` starts with `importlib.reload(es_service)` so edits to the service module are picked up
  on Streamlit's hot reload. Keep it.
- Severity colours live in `SEV_COLORS` and are used by metrics, sparklines, and the pie. Do not
  hardcode severity colours elsewhere.
- Card styling comes from `st.container(border=True)` plus a CSS override on
  `stVerticalBlockBorderWrapper`; any bordered container will render as a card.
- The detail table is capped at `TABLE_ROW_LIMIT` (1000) rows, newest first, and says so in its
  caption. There is no pagination.
- `requirements.txt` does not pin Streamlit. The production image is whatever was current at build
  time; DOM test selectors in this file were checked against 1.63.

## Release and deployment

Versioning is file-based: `VERSION` (currently `1.0.1`) is the Docker image tag and is shown in the
dashboard footer. Bumping `VERSION` and pushing to `master`/`main` (or a `v*` tag) is how a release
ships.

`.github/workflows/ci-cd.yml` runs three jobs:

1. `validate` — compileall, ruff (critical rules only), hadolint, actionlint, and a Trivy filesystem
   scan that **fails the build on any fixable HIGH/CRITICAL** in dependencies. When this gate fails,
   the fix is usually a version bump in `requirements.txt` (see the urllib3 commit in history).
2. `build-and-push` — builds the image, Trivy-scans it with the same gate, then pushes to
   `ghcr.io/<owner>/<repo>:<VERSION>` and `:latest`. Skipped on pull requests.
3. `update-manifest` — rewrites the `image:` line in `projects/<repo-name>/deployment.yaml` in the
   `HuntingYuk/k3s-manifest` repo over SSH using the `MANIFEST_DEPLOY_KEY` secret (a write-enabled
   deploy key of that repo; org deploy keys were enabled on 2026-09-09 for this). Silently skipped
   when the secret is absent.

Third-party actions are pinned to commit SHAs with a version comment. `aquasecurity/trivy-action`
has had tags deleted upstream before; check that every `uses:` ref still resolves before assuming
CI will pass.

### Cluster side (Rancher Fleet, not Flux)

The `kubeth` cluster (kube context `kubeth`) runs **Rancher Fleet**, which watches
`HuntingYuk/k3s-manifest` via GitRepo objects in namespace `fleet-local` (one per project, polling
every 1m) and applies `projects/dashboard-cve/deployment.yaml` into namespace `default`.

- All GitRepos share one basic-auth secret, `fleet-local/auth-fnmw4` (user `luhtaf`, password = a
  classic PAT with `repo` + `read:packages`). The image pull secret `default/ghcr-secret` holds the
  same PAT. Both were set on 2026-09-11 with a one-year expiry, so **they expire around
  2027-09-11**. When Fleet reports "authentication required: Invalid username or token" on every
  GitRepo, this token has expired; deploys stop silently (it happened from 2026-07-06 to
  2026-09-11).
- Fine-grained PATs do not work here: GHCR only accepts classic PATs, and the org rejected the
  fine-grained token for its repos.
- Outbound TCP 22 from the cluster is blocked (`ssh.github.com:443` too), so Fleet must use HTTPS.
  SSH deploy keys were tried and reverted.
- Quick health check: `kubectl --context kubeth get gitrepos.fleet.cattle.io -n fleet-local` should
  show the latest manifest commit and `GitPolling True`.

`dashboard-cve.service` is a systemd unit for a bare-VM deployment using the venv; paths and user in
it are placeholders that must be edited per host.
