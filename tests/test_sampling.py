from scanner.sampling import recent_sample, reservoir_sample, stratified_sample_by_group


def test_reservoir_sample_respects_limit():
    result = reservoir_sample(range(1000), limit=10, seed=1)
    assert len(result) == 10


def test_reservoir_sample_deterministic_for_same_seed():
    a = reservoir_sample(range(1000), limit=10, seed=42)
    b = reservoir_sample(range(1000), limit=10, seed=42)
    assert a == b


def test_reservoir_sample_differs_for_different_seed():
    a = reservoir_sample(range(1000), limit=10, seed=1)
    b = reservoir_sample(range(1000), limit=10, seed=2)
    assert a != b


def test_reservoir_sample_smaller_than_limit_returns_all():
    result = reservoir_sample(range(5), limit=10, seed=1)
    assert sorted(result) == [0, 1, 2, 3, 4]


def test_reservoir_sample_zero_limit():
    assert reservoir_sample(range(10), limit=0, seed=1) == []


def test_recent_sample_returns_last_n_in_order():
    result = recent_sample(range(100), limit=5)
    assert result == [95, 96, 97, 98, 99]


def test_recent_sample_smaller_than_limit():
    result = recent_sample(range(3), limit=5)
    assert result == [0, 1, 2]


def test_stratified_sample_splits_evenly_with_remainder_to_first_groups():
    groups = {
        "a": iter(range(100)),
        "b": iter(range(100, 200)),
        "c": iter(range(200, 300)),
    }
    result = stratified_sample_by_group(groups, limit=10, seed=1)
    # 10 / 3 groups -> quotas of 4, 3, 3 (remainder to "a", first alphabetically)
    assert len(result) == 10
    from_a = [x for x in result if 0 <= x < 100]
    from_b = [x for x in result if 100 <= x < 200]
    from_c = [x for x in result if 200 <= x < 300]
    assert len(from_a) == 4
    assert len(from_b) == 3
    assert len(from_c) == 3


def test_stratified_sample_deterministic():
    def make_groups():
        return {"a": iter(range(50)), "b": iter(range(50, 100))}

    a = stratified_sample_by_group(make_groups(), limit=8, seed=7)
    b = stratified_sample_by_group(make_groups(), limit=8, seed=7)
    assert a == b
