from aegismcp.normalizer import Normalizer


def test_normalizer_recursion_depth():
    """Test recursion depth protection."""
    deep_dict = {}
    current = deep_dict
    for i in range(150):
        current["next"] = {}
        current = current["next"]

    # Should not crash - recursion limited to 100 levels
    normalized = Normalizer.normalize_dict(deep_dict)
    # At depth 101, it returns empty dict, so we should have 101 levels of nesting
    # (since we start at depth=0 and check depth > 100)
    assert len(normalized) == 1
    assert "next" in normalized

    # Verify depth is capped at 101
    current = normalized
    depth = 0
    while isinstance(current, dict) and "next" in current:
        current = current["next"]
        depth += 1
    assert depth == 101  # Should have exactly 101 levels (0-100)

def test_normalizer_large_input():
    """Test large input handling."""
    large_input = "a" * 15 * 1024 * 1024 # 15MB
    normalized = Normalizer.normalize(large_input)
    assert len(normalized) <= 10 * 1024 * 1024 # 10MB limit
