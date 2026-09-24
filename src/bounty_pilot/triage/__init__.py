"""Triage: heuristic ranking (always on) with optional LLM re-ranking."""

from __future__ import annotations

from ..config import LLMSettings
from ..diff import Diff
from .heuristic import TriageItem, rank
from .llm import LLMError, Post, rerank


def triage(diff: Diff, llm: LLMSettings | None = None, post: Post | None = None) -> tuple[list[TriageItem], str | None]:
    """Return (ranked items, warning). The LLM only augments; failures fall back silently-safe."""
    items = rank(diff)
    if llm is None or not llm.enabled:
        return items, None
    try:
        return rerank(items, llm, post), None
    except LLMError as exc:
        return items, f"LLM triage unavailable ({exc}); using heuristic ranking"


__all__ = ["LLMError", "TriageItem", "rank", "rerank", "triage"]
