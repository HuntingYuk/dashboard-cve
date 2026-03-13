import os
import elasticsearch
from elasticsearch import Elasticsearch
import urllib3
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    url = os.getenv("ES_URL")
    username = os.getenv("ES_USERNAME")
    password = os.getenv("ES_PASSWORD")
    
    # Create the client with SSL verification disabled
    client = Elasticsearch(
        url,
        basic_auth=(username, password),
        verify_certs=False,
        ssl_show_warn=False
    )
    return client

def _build_bool_query(search_text=None, severity_filter=None, date_filter=None, date_field="published", score_range=(0, 10), kev_filter=False, epss_range=(0, 1), vendor_filter=None, product_filter=None, cvss_version_filter=None, status_filter=None):
    query = {
        "bool": {
            "must": []
        }
    }
    
    if search_text:
        query["bool"]["must"].append({
            "multi_match": {
                "query": search_text,
                "fields": ["desc", "id", "sev"] 
            }
        })
        
    if severity_filter and severity_filter != "All":
        if isinstance(severity_filter, list):
            if len(severity_filter) > 0:
                 query["bool"]["must"].append({
                    "terms": {
                        "sev.keyword": severity_filter
                    }
                })
        else:
            query["bool"]["must"].append({
                "term": {
                    "sev.keyword": severity_filter
                }
            })
            
    if status_filter and len(status_filter) > 0:
        query["bool"]["must"].append({
            "terms": {
                "vulnStatus.keyword": status_filter
            }
        })

    if date_filter:
        start_date = date_filter
        end_date = date_filter
        
        if isinstance(date_filter, (list, tuple)):
            start_date = str(date_filter[0]).split(' ')[0]
            # Handle case where date_filter might be (start_date,) during selection
            if len(date_filter) > 1:
                end_date = str(date_filter[1]).split(' ')[0]
            else:
                end_date = start_date
        else:
            start_date = str(date_filter).split(' ')[0]
            end_date = start_date
            
        query["bool"]["must"].append({
            "range": {
                date_field: {
                    "gte": f"{start_date}T00:00:00",
                    "lte": f"{end_date}T23:59:59"
                }
            }
        })
    
    if score_range:
        query["bool"]["must"].append({
            "range": {
                "score": {
                    "gte": score_range[0],
                    "lte": score_range[1]
                }
            }
        })

    if kev_filter:
        query["bool"]["must"].append({
            "term": {
                "hasCisa": True
            }
        })
        
    if epss_range and epss_range[0] > 0:
        query["bool"]["must"].append({
            "range": {
                "epss": {
                    "gte": epss_range[0],
                    "lte": epss_range[1]
                }
            }
        })

    # New Filters: Vendor and Product
    if vendor_filter:
        query["bool"]["must"].append({
            "match": {
                "vendors": vendor_filter
            }
        })
        
    if product_filter:
        query["bool"]["must"].append({
            "match": {
                "products": product_filter
            }
        })
        
    # CVSS Version Filter
    if cvss_version_filter and len(cvss_version_filter) > 0:
        # User selects: "3.1", "3.0", "2.0"
        # Data has "source": "v31", "v30" (or v3), "v2"
        mapped_versions = []
        for v in cvss_version_filter:
            if v == "3.1":
                mapped_versions.append("v31")
            elif v == "3.0":
                mapped_versions.append("v30") # assuming standard mapping, or check if data uses 'v3'
                mapped_versions.append("v3")  # covering both just in case
            elif v == "2.0":
                mapped_versions.append("v2")
        
        if mapped_versions:
             query["bool"]["must"].append({
                "terms": {
                    "source.keyword": mapped_versions
                }
            })

    return query

def fetch_cve_data(index_pattern="list-cve-*", size=1000, search_text=None, severity_filter=None, date_filter=None, date_field="published", score_range=(0, 10), kev_filter=False, epss_range=(0, 1), vendor_filter=None, product_filter=None, cvss_version_filter=None, status_filter=None):
    client = get_es_client()
    
    query = _build_bool_query(
        search_text, severity_filter, date_filter, date_field, 
        score_range, kev_filter, epss_range, vendor_filter, product_filter, cvss_version_filter, status_filter
    )
    
    response = client.search(
        index=index_pattern,
        body={
            "size": size,
            "query": query,
            "sort": [{"published": {"order": "desc"}}],
            "track_total_hits": True
        }
    )
    
    hits = response['hits']['hits']
    
    data = []
    for hit in hits:
        source = hit['_source']
        source['_id'] = hit['_id']
        source['_index'] = hit['_index']
        data.append(source)
        
    return pd.DataFrame(data), response['hits']['total']['value']

def fetch_summary_stats(index_pattern="list-cve-*", date_field="published", search_text=None, severity_filter=None, date_filter=None, score_range=(0, 10), kev_filter=False, epss_range=(0, 1), vendor_filter=None, product_filter=None, cvss_version_filter=None, status_filter=None):
    """
    Fetches aggregations for charts WITH respecting all filters.
    """
    client = get_es_client()
    
    # Reuse the same query logic so stats match the table
    query = _build_bool_query(
        search_text, severity_filter, date_filter, date_field, 
        score_range, kev_filter, epss_range, vendor_filter, product_filter, cvss_version_filter, status_filter
    )
    
    # Determine sensible interval for sparklines/trends
    interval = "year"
    if date_filter:
        try:
            # Check if range
            if isinstance(date_filter, (list, tuple)) and len(date_filter) > 1:
                 # Check delta
                 d1 = pd.to_datetime(str(date_filter[0]))
                 d2 = pd.to_datetime(str(date_filter[1]))
                 delta_days = (d2 - d1).days
                 
                 if delta_days > 730: # > 2 years
                     interval = "year"
                 elif delta_days > 60: # > 2 months
                     interval = "month"
                 elif delta_days > 14: # > 2 weeks
                     interval = "week"
                 else:
                     interval = "day"
            elif isinstance(date_filter, (str,  pd.Timestamp, type(pd.to_datetime("today").date()))):
                 # Single day selected?
                 interval = "hour"
        except:
            interval = "year"

    aggs_query = {
        "size": 0,
        "query": query, # Apply filters to aggregation
        "aggs": {
            "severity_counts": {
                "terms": {"field": "sev.keyword", "size": 10}
            },
            "severity_over_time": {
                "terms": {"field": "sev.keyword", "size": 5},
                "aggs": {
                    "history": {
                        "date_histogram": {
                            "field": date_field,
                            "calendar_interval": interval, 
                            "min_doc_count": 0
                        }
                    }
                }
            },
            "score_histogram": {
                "histogram": {"field": "score", "interval": 1}
            },
            "activity_over_time": {
                "date_histogram": {
                    "field": date_field,
                    "calendar_interval": "year",
                    "format": "yyyy"
                }
            },
            "top_vendors": {
                "terms": {"field": "vendors.keyword", "size": 5},
                "aggs": {
                    "history": {
                        "date_histogram": {
                            "field": date_field,
                            "calendar_interval": "year",
                            "format": "yyyy"
                        }
                    }
                }
            },
            "top_products": {
                "terms": {"field": "products.keyword", "size": 5},
                "aggs": {
                    "history": {
                        "date_histogram": {
                            "field": date_field,
                            "calendar_interval": "year",
                            "format": "yyyy"
                        }
                    }
                }
            },
            "vuln_status_counts": {
                "terms": {"field": "vulnStatus.keyword", "size": 10}
            },
            "top_weaknesses": {
                "terms": {"field": "original.weaknesses.description.value.keyword", "size": 5}
            },
            "unique_vendors": {
                "cardinality": {"field": "vendors.keyword"}
            },
            "unique_products": {
                "cardinality": {"field": "products.keyword"}
            },
            "kev_count": {
                "filter": {"term": {"hasCisa": True}}
            }
        }
    }
    
    response = client.search(index=index_pattern, body=aggs_query)
    return response['aggregations']
