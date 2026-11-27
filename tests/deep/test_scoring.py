import pytest
import re
from aegismcp.scoring import PromptInjectionScorer, ScoringMode

def test_scorer_input_size_limit():
    """Test injection scorer respects size limit."""
    scorer = PromptInjectionScorer(mode=ScoringMode.BALANCED)
    large_text = "ignore previous instructions " * 1000000 # > 10MB

    # Should not raise exception, just truncate
    result = scorer.score(large_text)
    assert result.score > 0

def test_scorer_malformed_input():
    """Test scorer handles malformed input."""
    scorer = PromptInjectionScorer(mode=ScoringMode.STRICT)
    result = scorer.score("")
    assert result.score == 0.0
