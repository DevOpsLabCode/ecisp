from app.orgscan import severity


def test_checkov_known_and_unknown():
    assert severity.checkov("CRITICAL") == "critical"
    assert severity.checkov("high") == "high"  # case-insensitive
    assert severity.checkov("something-unrecognized") == "medium"


def test_bandit_scale():
    assert severity.bandit("HIGH") == "high"
    assert severity.bandit("LOW") == "low"
    assert severity.bandit("") == "medium"


def test_semgrep_scale():
    assert severity.semgrep("ERROR") == "high"
    assert severity.semgrep("WARNING") == "medium"
    assert severity.semgrep("INFO") == "info"


def test_gosec_scale():
    assert severity.gosec("HIGH") == "high"
    assert severity.gosec("unknown") == "medium"


def test_spotbugs_priority():
    assert severity.spotbugs(1) == "high"
    assert severity.spotbugs(2) == "medium"
    assert severity.spotbugs(3) == "low"
    assert severity.spotbugs(99) == "medium"


def test_eslint_scale():
    assert severity.eslint(2) == "high"
    assert severity.eslint(1) == "medium"
    assert severity.eslint(0) == "medium"


def test_brakeman_confidence():
    assert severity.brakeman("High") == "high"
    assert severity.brakeman("Weak") == "low"
    assert severity.brakeman("???") == "medium"


def test_roslyn_scale():
    assert severity.roslyn("Error") == "high"
    assert severity.roslyn("Warning") == "medium"
    assert severity.roslyn("Info") == "info"
    assert severity.roslyn("???") == "medium"
