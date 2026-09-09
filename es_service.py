import math
import os
from pathlib import Path

import elasticsearch
import pandas as pd
import urllib3
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

# Suppress InsecureRequestWarning (on-prem ES uses a self-signed certificate)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_INDEX = "list-cve"
FULL_SCORE_RANGE = (0.0, 10.0)
FULL_EPSS_RANGE = (0.0, 1.0)

# UI label -> values seen in `source.keyword`. The index uses "v3.1" / "v3.0" / "v2";
# the older spellings are kept so a re-index with a different convention keeps working.
CVSS_VERSION_SOURCES = {
    "3.1": ["v3.1", "v31"],
    "3.0": ["v3.0", "v30", "v3"],
    "2.0": ["v2", "v2.0"],
}

CWE_FIELD = "original.weaknesses.description.value.keyword"

# `score` is mapped as long (decimals truncated at index time). `v3.score` is a float,
# so prefer it and fall back to `score` for CVEs that only carry CVSS v2.
_EFFECTIVE_SCORE_SCRIPT = (
    "if (doc.containsKey('v3.score') && doc['v3.score'].size() > 0) { return doc['v3.score'].value; }"
    "if (doc['score'].size() > 0) { return doc['score'].value; }"
    "return -1;"
)

PRIORITY_SORTS = {
    "kev": ["kev", "score", "epss"],
    "score": ["score", "epss", "kev"],
    "epss": ["epss", "score", "kev"],
}

_SORT_CLAUSES = {
    "kev": {"hasCisa": {"order": "desc", "missing": "_last"}},
    "score": {
        "_script": {
            "type": "number",
            "order": "desc",
            "script": {"lang": "painless", "source": _EFFECTIVE_SCORE_SCRIPT},
        }
    },
    "epss": {"epss": {"order": "desc", "missing": "_last"}},
}

PRIORITY_SOURCE_FIELDS = [
    "id", "sev", "score", "epss", "percentile", "hasCisa", "vulnStatus",
    "published", "lastModified", "vendors", "products", "desc",
    "cisa.cisaActionDue", "cisa.cisaExploitAdd", "cisa.cisaVulnerabilityName",
]


def _validate_elasticsearch_client_version():
    version = getattr(elasticsearch, "__version__", None)
    major = version[0] if isinstance(version, tuple) and version else None
    if major != 8:
        raise RuntimeError(
            "Installed elasticsearch client is incompatible with Elasticsearch 8.x. "
            "Install a version in the 8.x series, for example: pip install 'elasticsearch>=8.17.0,<9'"
        )


def get_es_client():
    _validate_elasticsearch_client_version()
    url = os.getenv("ES_URL", "").strip()
    cloud_id = os.getenv("ES_CLOUD_ID", "").strip()
    username = os.getenv("ES_USERNAME", "").strip()
    password = os.getenv("ES_PASSWORD", "").strip()

    if not url and not cloud_id:
        raise RuntimeError(
            "Missing Elasticsearch connection config. Set one of ES_URL or ES_CLOUD_ID in .env"
        )

    missing_auth = []
    if not username:
        missing_auth.append("ES_USERNAME")
    if not password:
        missing_auth.append("ES_PASSWORD")
    if missing_auth:
        raise RuntimeError(
            f"Missing Elasticsearch credential(s): {', '.join(missing_auth)}"
        )

    if cloud_id:
        return Elasticsearch(cloud_id=cloud_id, basic_auth=(username, password))

    return Elasticsearch(
        url,
        basic_auth=(username, password),
        verify_certs=False,
        ssl_show_warn=False,
    )


def _date_bounds(date_filter):
    """Normalise a date / (start, end) / (start,) into ISO day strings."""
    if isinstance(date_filter, (list, tuple)):
        if not date_filter:
            return None, None
        start = str(date_filter[0]).split(" ")[0]
        end = str(date_filter[1]).split(" ")[0] if len(date_filter) > 1 else start
        return start, end
    day = str(date_filter).split(" ")[0]
    return day, day


def _build_bool_query(
    search_text=None,
    severity_filter=None,
    date_filter=None,
    date_field="published",
    score_range=FULL_SCORE_RANGE,
    kev_filter=False,
    epss_range=FULL_EPSS_RANGE,
    vendor_filter=None,
    product_filter=None,
    cwe_filter=None,
    cvss_version_filter=None,
    status_filter=None,
    year_filter=None,
):
    must = []

    if search_text:
        must.append({
            "multi_match": {
                "query": search_text,
                "fields": ["desc", "id", "sev"],
            }
        })

    if severity_filter and severity_filter != "All":
        values = severity_filter if isinstance(severity_filter, list) else [severity_filter]
        if values:
            must.append({"terms": {"sev.keyword": values}})

    if status_filter:
        must.append({"terms": {"vulnStatus.keyword": list(status_filter)}})

    if year_filter and year_filter != "All":
        must.append({
            "range": {
                date_field: {
                    "gte": f"{year_filter}-01-01T00:00:00",
                    "lte": f"{year_filter}-12-31T23:59:59",
                }
            }
        })

    if date_filter:
        start_date, end_date = _date_bounds(date_filter)
        if start_date:
            must.append({
                "range": {
                    date_field: {
                        "gte": f"{start_date}T00:00:00",
                        "lte": f"{end_date}T23:59:59",
                    }
                }
            })

    # Only constrain the score when the user narrowed the slider. Applying the full
    # 0-10 range would silently drop ~26k CVEs that have no score yet (Received,
    # Rejected, Deferred).
    if score_range and tuple(score_range) != FULL_SCORE_RANGE:
        low, high = float(score_range[0]), float(score_range[1])
        must.append({
            "bool": {
                "should": [
                    {"range": {"v3.score": {"gte": low, "lte": high}}},
                    {
                        "bool": {
                            "must_not": {"exists": {"field": "v3.score"}},
                            # `score` is an integer field, so widen the lower bound to
                            # keep e.g. 7.5-7.9 (stored as 7) when the user asks for >= 7.5.
                            "filter": {"range": {"score": {"gte": math.floor(low), "lte": high}}},
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        })

    if kev_filter:
        must.append({"term": {"hasCisa": True}})

    if epss_range and tuple(epss_range) != FULL_EPSS_RANGE:
        must.append({"range": {"epss": {"gte": epss_range[0], "lte": epss_range[1]}}})

    if vendor_filter:
        must.append({"match": {"vendors": vendor_filter}})

    if product_filter:
        must.append({"match": {"products": product_filter}})

    if cwe_filter:
        must.append({"term": {CWE_FIELD: cwe_filter}})

    if cvss_version_filter:
        sources = []
        for version in cvss_version_filter:
            sources.extend(CVSS_VERSION_SOURCES.get(str(version), []))
        if sources:
            must.append({"terms": {"source.keyword": sources}})

    return {"bool": {"must": must}}


def fetch_cve_data(index_pattern=DEFAULT_INDEX, size=1000, **filters):
    """Newest-first rows for the detail table plus the total number of matches."""
    client = get_es_client()
    query = _build_bool_query(**filters)

    response = client.search(
        index=index_pattern,
        body={
            "size": size,
            "query": query,
            "sort": [{"published": {"order": "desc"}}],
            "track_total_hits": True,
        },
    )

    data = []
    for hit in response["hits"]["hits"]:
        source = hit["_source"]
        source["_id"] = hit["_id"]
        source["_index"] = hit["_index"]
        data.append(source)

    return pd.DataFrame(data), response["hits"]["total"]["value"]


def fetch_priority_cves(index_pattern=DEFAULT_INDEX, size=50, sort_mode="kev", **filters):
    """
    Top-N CVEs ranked by exploitation risk, respecting the same filters as the table.
    sort_mode: "kev" (KEV first, then CVSS, then EPSS), "score" (CVSS first) or "epss" (EPSS first).
    """
    client = get_es_client()
    query = _build_bool_query(**filters)
    order = PRIORITY_SORTS.get(sort_mode, PRIORITY_SORTS["kev"])

    response = client.search(
        index=index_pattern,
        body={
            "size": size,
            "_source": PRIORITY_SOURCE_FIELDS,
            "query": query,
            "sort": [_SORT_CLAUSES[name] for name in order],
        },
    )

    rows = []
    for hit in response["hits"]["hits"]:
        source = hit["_source"]
        cisa = source.get("cisa") or {}
        vendors = source.get("vendors")
        products = source.get("products")
        rows.append({
            "id": source.get("id"),
            "hasCisa": bool(source.get("hasCisa", False)),
            "sev": source.get("sev"),
            "score": source.get("score"),
            "epss": source.get("epss"),
            "percentile": source.get("percentile"),
            "vulnStatus": source.get("vulnStatus"),
            "cisaActionDue": cisa.get("cisaActionDue"),
            "cisaVulnerabilityName": cisa.get("cisaVulnerabilityName"),
            "published": source.get("published"),
            "lastModified": source.get("lastModified"),
            "vendors": ", ".join(vendors) if isinstance(vendors, list) else vendors,
            "products": ", ".join(products) if isinstance(products, list) else products,
            "desc": source.get("desc"),
        })

    return pd.DataFrame(rows)


def _histogram_interval(date_filter):
    """Pick a calendar interval that gives a readable number of buckets."""
    if not date_filter:
        return "year"
    try:
        if isinstance(date_filter, (list, tuple)) and len(date_filter) > 1:
            delta_days = (pd.to_datetime(str(date_filter[1])) - pd.to_datetime(str(date_filter[0]))).days
            if delta_days > 730:
                return "year"
            if delta_days > 60:
                return "month"
            if delta_days > 14:
                return "week"
            return "day"
        return "hour"
    except Exception:
        return "year"


def fetch_summary_stats(index_pattern=DEFAULT_INDEX, **filters):
    """
    Aggregations for metrics and charts, respecting the same filters as the tables.
    The chosen date-histogram interval is returned under the "_interval" key.
    """
    client = get_es_client()
    query = _build_bool_query(**filters)
    date_field = filters.get("date_field") or "published"
    interval = _histogram_interval(filters.get("date_filter"))

    yearly = {"date_histogram": {"field": date_field, "calendar_interval": "year", "format": "yyyy"}}

    aggs_query = {
        "size": 0,
        "query": query,
        "aggs": {
            "severity_counts": {"terms": {"field": "sev.keyword", "size": 10}},
            "severity_over_time": {
                "terms": {"field": "sev.keyword", "size": 5},
                "aggs": {
                    "history": {
                        "date_histogram": {
                            "field": date_field,
                            "calendar_interval": interval,
                            "min_doc_count": 0,
                        }
                    }
                },
            },
            "score_histogram": {"histogram": {"field": "score", "interval": 1}},
            "activity_over_time": {
                "date_histogram": {"field": date_field, "calendar_interval": interval}
            },
            "top_vendors": {
                "terms": {"field": "vendors.keyword", "size": 5},
                "aggs": {"history": yearly},
            },
            "top_products": {
                "terms": {"field": "products.keyword", "size": 5},
                "aggs": {"history": yearly},
            },
            "vuln_status_counts": {"terms": {"field": "vulnStatus.keyword", "size": 10}},
            "top_weaknesses": {
                # NVD-CWE-noinfo / NVD-CWE-Other are placeholders, not weaknesses.
                "terms": {"field": CWE_FIELD, "size": 5, "exclude": "NVD-CWE-.*"}
            },
            "unique_vendors": {"cardinality": {"field": "vendors.keyword"}},
            "unique_products": {"cardinality": {"field": "products.keyword"}},
            "kev_count": {"filter": {"term": {"hasCisa": True}}},
        },
    }

    response = client.search(index=index_pattern, body=aggs_query)
    aggregations = response["aggregations"]
    aggregations["_interval"] = interval
    return aggregations
