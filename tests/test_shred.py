"""Strict red tests for the crypto-shredding exercise.

Each test asserts the contractual behavior, not the current buggy behavior.
At repository delivery all fifteen tests fail because every public stub raises
NotImplementedError.
"""

import hashlib
import hmac

import pytest

from shred.api import (
    build_tree,
    decrypt_check,
    derive_child,
    destroy,
    is_destroyed,
    purge_cache,
    shred_batch,
    verify_no_residual,
)


def _spec():
    return {
        "root": [(0, "left"), (1, "right")],
        "left": [(0, "left-a"), (1, "left-b")],
        "right": [(0, "right-a")],
    }


def _make_tree():
    return build_tree("root", _spec())


def _seal(key, plaintext):
    tag = hmac.new(key, plaintext, hashlib.sha256).digest()
    return tag + plaintext


def test_destroy_propagates_to_all_descendants():
    tree = _make_tree()

    result = destroy(tree, "left", 100)

    assert result["at"] == 100
    assert result["count"] == 3
    assert set(result["destroyed"]) == {"left", "left-a", "left-b"}
    for node_id in ("left", "left-a", "left-b"):
        assert is_destroyed(tree, node_id) is True
    for node_id in ("root", "right", "right-a"):
        assert is_destroyed(tree, node_id) is False


def test_is_destroyed_true_for_descendant_of_destroyed_ancestor():
    tree = _make_tree()
    root = tree["nodes"]["root"]
    root["destroyed"] = True
    root["destroyed_at"] = 1
    root["key"] = None

    assert is_destroyed(tree, "left-a") is True
    assert is_destroyed(tree, "right-a") is True
    assert tree["nodes"]["left-a"]["destroyed"] is False


def test_derive_child_depends_on_parent_key_and_index():
    parent_a = b"\x11" * 32
    parent_b = b"\x22" * 32

    a0 = derive_child(parent_a, 0)
    a1 = derive_child(parent_a, 1)
    b0 = derive_child(parent_b, 0)
    b1 = derive_child(parent_b, 1)

    assert isinstance(a0, bytes)
    assert len(a0) == 32
    assert a0 == derive_child(parent_a, 0)
    assert len({a0, a1, b0, b1}) == 4


def test_build_tree_rejects_duplicate_sibling_index_and_cycles():
    with pytest.raises(ValueError):
        build_tree("root", {"root": [(0, "left"), (0, "right")]})

    with pytest.raises(ValueError):
        build_tree("root", {"root": [(0, "a")], "a": [(0, "root")]})


def test_decrypt_check_rechecks_destroyed_status():
    tree = _make_tree()
    key = tree["nodes"]["left-a"]["key"]
    ciphertext = _seal(key, b"node-local-secret")
    tree["nodes"]["left-a"]["destroyed"] = True
    tree["nodes"]["left-a"]["destroyed_at"] = 5

    assert key is not None
    assert decrypt_check(tree, "left-a", ciphertext) is False


def test_purge_cache_removes_keys_of_descendants_of_destroyed_ancestor():
    tree = _make_tree()
    parent_key = tree["nodes"]["left"]["key"]
    child_key = tree["nodes"]["left-a"]["key"]
    cache = {
        "left-a": {
            "key": child_key,
            "source": {"parent_key": parent_key, "index": 0},
        }
    }
    tree["nodes"]["left"]["destroyed"] = True
    tree["nodes"]["left"]["key"] = None

    removed = purge_cache(cache, tree)

    assert removed == 1
    assert "left-a" not in cache


def test_purge_cache_removes_derivation_source_not_only_key():
    tree = _make_tree()
    parent_key = tree["nodes"]["left"]["key"]
    child_key = tree["nodes"]["left-a"]["key"]
    cache = {
        "left-a": {
            "key": child_key,
            "source": {"parent_key": parent_key, "index": 0},
        }
    }
    destroy(tree, "left-a", 7)

    removed = purge_cache(cache, tree)

    assert removed == 1
    entry = cache.get("left-a", {})
    assert "key" not in entry
    assert "source" not in entry


def test_verify_no_residual_checks_every_backup():
    tree = _make_tree()
    key = tree["nodes"]["left-a"]["key"]
    destroy(tree, "left-a", 10)
    stale = _seal(key, b"stale-copy")
    backups = [
        {
            "id": "primary",
            "node_id": "left-a",
            "key_snapshot": key,
            "ciphertext": b"not-a-valid-envelope",
            "filename": "primary.bin",
            "primary": True,
        },
        {
            "id": "backup-2",
            "node_id": "left-a",
            "key_snapshot": key,
            "ciphertext": stale,
            "filename": "backup-2.bin",
            "primary": False,
        },
    ]

    assert verify_no_residual(tree, backups) == ["backup-2"]


def test_verify_no_residual_uses_content_not_filename():
    tree = _make_tree()
    key = tree["nodes"]["left-a"]["key"]
    destroy(tree, "left-a", 11)
    backups = [
        {
            "id": "looks-dirty",
            "node_id": "left-a",
            "key_snapshot": key,
            "ciphertext": b"garbage",
            "filename": "residual.bak",
            "primary": False,
        },
        {
            "id": "renamed",
            "node_id": "left-a",
            "key_snapshot": key,
            "ciphertext": _seal(key, b"still-in-backup"),
            "filename": "shredded_clean.txt",
            "primary": False,
        },
    ]

    assert verify_no_residual(tree, backups) == ["renamed"]


def test_shred_batch_requests_are_independent():
    tree_one = _make_tree()
    tree_two = _make_tree()

    batch = shred_batch(
        [
            {"tree": tree_one, "node_id": "left"},
            {"tree": tree_two, "node_id": "left"},
        ],
        {},
        20,
    )

    assert len(batch["results"]) == 2
    assert is_destroyed(tree_one, "left-a") is True
    assert is_destroyed(tree_two, "left-a") is True
    assert is_destroyed(tree_two, "left-b") is True
    assert is_destroyed(tree_one, "right") is False
    assert is_destroyed(tree_two, "right") is False


def test_destroyed_node_decrypt_fails():
    tree = _make_tree()
    key = tree["nodes"]["left-a"]["key"]
    ciphertext = _seal(key, b"node-secret")
    assert decrypt_check(tree, "left-a", ciphertext) is True

    destroy(tree, "left-a", 30)

    assert decrypt_check(tree, "left-a", ciphertext) is False


def test_destroyed_parent_child_decrypt_fails():
    tree = _make_tree()
    key = tree["nodes"]["left-a"]["key"]
    ciphertext = _seal(key, b"child-secret")

    destroy(tree, "left", 31)

    assert is_destroyed(tree, "left-a") is True
    assert decrypt_check(tree, "left-a", ciphertext) is False


def test_purged_cache_cannot_rederive_destroyed_key():
    tree = _make_tree()
    parent_key = tree["nodes"]["left"]["key"]
    child_key = tree["nodes"]["left-a"]["key"]
    cache = {
        "left-a": {
            "key": child_key,
            "source": {"parent_key": parent_key, "index": 0},
        }
    }
    destroy(tree, "left", 32)

    purge_cache(cache, tree)

    assert cache.get("left-a") is None
    assert decrypt_check(tree, "left-a", _seal(child_key, b"x")) is False


def test_backup_residual_is_detected():
    tree = _make_tree()
    key = tree["nodes"]["left-b"]["key"]
    destroy(tree, "left-b", 40)
    backups = [
        {
            "id": "primary",
            "node_id": "left-b",
            "key_snapshot": key,
            "ciphertext": _seal(key, b"primary-residual"),
            "filename": "primary.bak",
        },
        {
            "id": "clean",
            "node_id": "left-b",
            "key_snapshot": key,
            "ciphertext": b"garbage",
            "filename": "clean.bak",
        },
        {
            "id": "backup-2",
            "node_id": "left-b",
            "key_snapshot": key,
            "ciphertext": _seal(key, b"second-residual"),
            "filename": "backup-2.bak",
        },
    ]

    assert verify_no_residual(tree, backups) == ["primary", "backup-2"]


def test_batch_destruction_matches_individual_destruction():
    tree_one = _make_tree()
    tree_two = _make_tree()
    batch = shred_batch(
        [
            {"tree": tree_one, "node_id": "left"},
            {"tree": tree_two, "node_id": "right"},
        ],
        {},
        50,
    )

    single_tree_one = _make_tree()
    single_tree_two = _make_tree()
    singles = [
        destroy(single_tree_one, "left", 50),
        destroy(single_tree_two, "right", 50),
    ]

    assert batch["results"] == singles
    for node_id in ("left", "left-a", "left-b"):
        assert is_destroyed(tree_one, node_id) is True
    for node_id in ("right", "right-a"):
        assert is_destroyed(tree_two, node_id) is True