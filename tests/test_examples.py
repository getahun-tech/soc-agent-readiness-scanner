"""Every bundled example config must stay a valid, loadable starting
point -- these are what a user copies verbatim. A schema change that
breaks one of these without anyone noticing would hand out a broken
template, which is worse than no template at all.
"""

from pathlib import Path

import pytest

from scanner.config import load_config

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.mark.parametrize(
    "filename",
    ["demo.yaml", "splunk.yaml", "sentinel.yaml", "elastic.yaml"],
)
def test_example_config_loads_and_validates(filename):
    cfg = load_config(EXAMPLES / filename)
    assert cfg.sources, f"{filename} should declare at least one source"
    for source in cfg.sources:
        assert source.owner, f"{filename}: source '{source.name}' has no owner"


def test_splunk_template_uses_recommended_token_auth_by_default():
    cfg = load_config(EXAMPLES / "splunk.yaml")
    assert cfg.splunk.auth == "token"


def test_live_templates_default_to_the_cheapest_sample_strategy():
    # 'recent' needs no oversampling against Splunk/Sentinel; Elastic's
    # 'random' is server-side seeded, so it's equally cheap there.
    assert load_config(EXAMPLES / "splunk.yaml").defaults.sample_strategy == "recent"
    assert load_config(EXAMPLES / "sentinel.yaml").defaults.sample_strategy == "recent"
    assert load_config(EXAMPLES / "elastic.yaml").defaults.sample_strategy == "random"
