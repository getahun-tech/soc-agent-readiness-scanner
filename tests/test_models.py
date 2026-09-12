from scanner.models import flatten_record


def test_flatten_nested_objects_to_dotted_keys():
    doc = {"@timestamp": "t", "destination": {"ip": "10.0.0.2", "geo": {"city": "x"}}}
    assert flatten_record(doc) == {
        "@timestamp": "t",
        "destination.ip": "10.0.0.2",
        "destination.geo.city": "x",
    }


def test_flatten_keeps_lists_as_leaf_values():
    # A multivalue field is one field -- never exploded into tags.0/tags.1,
    # which would turn it into an unbounded set of high-cardinality keys.
    doc = {"related": {"hosts": ["a", "b"]}, "tags": [{"k": 1}]}
    assert flatten_record(doc) == {"related.hosts": ["a", "b"], "tags": [{"k": 1}]}


def test_flatten_drops_empty_objects():
    assert flatten_record({"a": {}, "b": 1}) == {"b": 1}


def test_flatten_respects_max_depth_by_keeping_deeper_levels_opaque():
    deep = {"a": {"b": {"c": {"d": 1}}}}
    assert flatten_record(deep, max_depth=2) == {"a.b.c": {"d": 1}}
    assert flatten_record(deep) == {"a.b.c.d": 1}


def test_flatten_passes_flat_records_through_unchanged():
    flat = {"host": "web01", "user": "alice", "n": 3, "none": None}
    assert flatten_record(flat) == flat
