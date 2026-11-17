"""Tests for the ecosystem abecedary collation."""

from __future__ import annotations

from acidbase.collation import abc_key, abc_sorted


def test_case_is_interleaved_not_capitals_first() -> None:
    """Orders A a B b ... rather than codepoint order's A B ... a b."""
    assert abc_sorted(["b", "B", "a", "A", "Z", "z"]) == ["A", "a", "B", "b", "Z", "z"]


def test_zone_p_punctuation_precedes_every_letter() -> None:
    """Sorts `_`, `[`, `^`, `` ` ``, `{`, `~` before `A`, unlike codepoint order."""
    assert abc_sorted(["a", "A", "~", "_", "[", "{", "^", "`"]) == ["[", "^", "_", "`", "{", "~", "A", "a"]


def test_zone_p_internal_order_follows_the_abecedary() -> None:
    """Keeps ASCII 33..63 first, then the inverted Spanish marks, then `@`, then 91..96."""
    assert abc_sorted(["@", "\u00a1", "\u00bf", "?", "!", "_"]) == ["!", "?", "\u00bf", "\u00a1", "@", "_"]


def test_proper_prefix_sorts_first() -> None:
    """Places `env` before `env/` and `env.bak/`."""
    assert abc_sorted(["env/", "env.bak/", "env"]) == ["env", "env.bak/", "env/"]


def test_accented_letter_follows_its_base_letter() -> None:
    """Sorts `á` after `A`/`a` and before `B`."""
    assert abc_key("A") < abc_key("a") < abc_key("\u00e1") < abc_key("B")


def test_gitignore_example_from_the_bug_report() -> None:
    """Merges rules from separate template sections into one abecedarian run."""
    rules = [".serena/", "*.backup", "*.bak", "app_backup/", "*$py.class", "/Backup.egg-info/", "__pycache__/"]
    assert abc_sorted(rules) == [
        "*$py.class",
        "*.backup",
        "*.bak",
        ".serena/",
        "/Backup.egg-info/",
        "__pycache__/",
        "app_backup/",
    ]
