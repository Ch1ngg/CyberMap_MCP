from cybermap_mcp.engines import Asset, merge_assets


def test_dedup_key_host_or_domain():
    assert Asset(ip="1.1.1.1", port=80, domain="d.com").dedup_key() == \
        ("1.1.1.1", 80, "d.com", None)
    assert Asset().dedup_key() is None


def test_as_dict_omits_none_and_empty():
    d = Asset(ip="1.1.1.1", sources=["fofa"]).as_dict()
    assert d == {"ip": "1.1.1.1", "sources": ["fofa"]}


def test_merge_dedups_and_merges_sources():
    a1 = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
               sources=["fofa"], title="first")
    a2 = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
               sources=["quake"])
    merged = merge_assets([a1, a2])
    assert len(merged) == 1
    assert merged[0].sources == ["fofa", "quake"]
    assert merged[0].title == "first"


def test_merge_backfills_empty_fields_from_later_asset():
    sparse = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
                   sources=["fofa"])
    rich = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
                 sources=["quake"], title="Tomcat", org="ACME")
    merged = merge_assets([sparse, rich])
    assert merged[0].title == "Tomcat"
    assert merged[0].org == "ACME"


def test_merge_does_not_overwrite_existing_fields():
    a1 = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
               sources=["fofa"], title="first")
    a2 = Asset(ip="1.1.1.1", port=80, host="a.com", protocol="http",
               sources=["quake"], title="second")
    assert merge_assets([a1, a2])[0].title == "first"


def test_merge_keeps_unkeyable_records_in_order():
    a = Asset(title="no identifiers", sources=["0zone"])
    b = Asset(url="http://x", sources=["0zone"])
    assert merge_assets([a, b]) == [a, b]
