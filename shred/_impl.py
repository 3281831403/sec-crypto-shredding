"""Core implementation module for the crypto-shredding exercise.

The public facade re-exports the eight functions below.  The signatures are
stable and match :mod:`shred.api`.

Tree schema
-----------
``build_tree`` returns a dictionary with two keys::

    {
        "root": "<root-id>",
        "nodes": {
            "<node-id>": {
                "id": "<node-id>",
                "parent": "<parent-id>" or None,
                "children": ["<child-id>", ...],
                "key": b"..." or None,
                "destroyed": False,
                "destroyed_at": None,
            },
            ...
        },
    }

A node key is 32 bytes.  Destroying a node clears its key material and sets
``destroyed`` to True; destroying an ancestor must make every descendant
unusable even if a descendant flag was missed.

Ciphertext schema
-----------------
The envelope used by ``decrypt_check`` and ``verify_no_residual`` is::

    tag (32 bytes) || plaintext

where ``tag == HMAC-SHA256(key, plaintext).digest()``.  The tests build
envelopes with the same convention.  Decryption means authenticating the
envelope and returning a boolean; the plaintext itself is not returned.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any


_ROOT_KEY_LABEL = b"sec-crypto-shredding/root-key/v1"
_CHILD_KEY_LABEL = b"sec-crypto-shredding/child-key/v1"
_TAG_SIZE = hashlib.sha256().digest_size


def _envelope_authenticates(key: Any, ciphertext: Any) -> bool:
    """Return whether ``ciphertext`` is a valid tag||plaintext envelope."""
    if not isinstance(key, (bytes, bytearray)):
        return False
    if not isinstance(ciphertext, (bytes, bytearray)):
        return False
    if len(ciphertext) < _TAG_SIZE:
        return False

    key_bytes = bytes(key)
    ciphertext_bytes = bytes(ciphertext)
    tag = ciphertext_bytes[:_TAG_SIZE]
    plaintext = ciphertext_bytes[_TAG_SIZE:]
    expected_tag = hmac.new(key_bytes, plaintext, hashlib.sha256).digest()
    return hmac.compare_digest(tag, expected_tag)


def build_tree(root: str, children: dict[str, list[tuple[int, str]]]) -> dict:
    """Build a key hierarchy from a root id and sibling index assignments.

    ``children`` maps a parent id to a sequence of ``(index, child_id)``
    pairs.  Every node except the root must occur exactly once as a child,
    every sibling index must be a unique non-negative integer, and the graph
    must be connected and acyclic.  Cycles, duplicate sibling indexes,
    duplicate child assignments and unreachable nodes must raise ValueError.

    The root key is derived deterministically from ``root`` so that two
    builds of the same hierarchy have identical key material.  Each child key
    is derived with ``derive_child(parent_key, index)``.
    """
    if not isinstance(root, str) or not root:
        raise ValueError("root must be a non-empty string")
    if not isinstance(children, dict):
        raise ValueError("children must be a dictionary")

    entries_by_parent: dict[str, list[tuple[int, str]]] = {}
    parent_of: dict[str, str] = {}
    all_node_ids = {root}

    for parent, assignments in children.items():
        if not isinstance(parent, str) or not parent:
            raise ValueError("parent ids must be non-empty strings")
        if not isinstance(assignments, (list, tuple)):
            raise ValueError("child assignments must be a sequence")

        all_node_ids.add(parent)
        entries: list[tuple[int, str]] = []
        seen_indexes: set[int] = set()

        for assignment in assignments:
            if not isinstance(assignment, (tuple, list)) or len(assignment) != 2:
                raise ValueError("each child assignment must be an (index, child_id) pair")

            index, child_id = assignment
            if not isinstance(index, int) or index < 0:
                raise ValueError("sibling index must be a non-negative integer")
            if not isinstance(child_id, str) or not child_id:
                raise ValueError("child id must be a non-empty string")
            if index in seen_indexes:
                raise ValueError(f"duplicate sibling index {index!r} for {parent!r}")
            if child_id == root:
                raise ValueError("root node cannot also be a child")
            if child_id in parent_of:
                raise ValueError(f"child {child_id!r} is assigned to more than one parent")

            seen_indexes.add(index)
            parent_of[child_id] = parent
            entries.append((index, child_id))
            all_node_ids.add(child_id)

        entries_by_parent[parent] = entries

    missing_parent = sorted(
        node_id for node_id in all_node_ids if node_id != root and node_id not in parent_of
    )
    if missing_parent:
        raise ValueError(f"nodes without a parent assignment: {missing_parent}")

    nodes: dict[str, dict[str, Any]] = {}
    for node_id in all_node_ids:
        nodes[node_id] = {
            "id": node_id,
            "parent": None if node_id == root else parent_of[node_id],
            "children": [child_id for _, child_id in entries_by_parent.get(node_id, ())],
            "key": None,
            "destroyed": False,
            "destroyed_at": None,
        }

    # Deterministically derive keys while traversing from the root.  The
    # traversal also proves reachability and rejects any remaining cycle.
    nodes[root]["key"] = hashlib.sha256(_ROOT_KEY_LABEL + root.encode("utf-8")).digest()
    visited: set[str] = set()
    stack = [root]

    while stack:
        node_id = stack.pop()
        if node_id in visited:
            raise ValueError("key hierarchy contains a cycle")
        visited.add(node_id)

        parent_key = nodes[node_id]["key"]
        entries = entries_by_parent.get(node_id, ())
        for index, child_id in entries:
            nodes[child_id]["key"] = derive_child(parent_key, index)

        for _, child_id in reversed(entries):
            stack.append(child_id)

    if visited != all_node_ids:
        unreachable = sorted(all_node_ids - visited)
        raise ValueError(f"key hierarchy contains unreachable nodes: {unreachable}")

    return {"root": root, "nodes": nodes}


def derive_child(parent_key: bytes, index: int) -> bytes:
    """Derive a 32-byte child key from parent key material and an index.

    The result must be deterministic.  Both the parent key and the index
    must affect the output: the same index under different parents and
    different indexes under the same parent must produce different keys.
    ``parent_key`` must be non-empty bytes and ``index`` must be a
    non-negative integer.
    """
    if not isinstance(parent_key, bytes) or not parent_key:
        raise ValueError("parent_key must be non-empty bytes")
    if not isinstance(index, int) or index < 0:
        raise ValueError("index must be a non-negative integer")

    index_bytes = str(index).encode("ascii")
    message = _CHILD_KEY_LABEL + b"\x00" + index_bytes
    return hmac.new(parent_key, message, hashlib.sha256).digest()


def destroy(tree: dict, node_id: str, now: Any) -> dict:
    """Destroy a node and every descendant, recursively.

    Every node in the subtree must be marked destroyed, stamped with ``now``,
    and have its key material cleared.  The return value is::

        {
            "destroyed": ["<node-id>", "<descendant-id>", ...],
            "count": <number of nodes in the subtree>,
            "at": now,
        }

    The ``destroyed`` list is in a deterministic pre-order traversal.  The
    operation is idempotent and a missing node id raises KeyError.
    """
    nodes = tree["nodes"]
    nodes[node_id]  # Raise KeyError for an unknown requested node.

    destroyed: list[str] = []
    seen: set[str] = set()
    stack = [node_id]

    while stack:
        current_id = stack.pop()
        if current_id in seen:
            continue
        seen.add(current_id)

        node = nodes[current_id]
        destroyed.append(current_id)
        node["destroyed"] = True
        node["destroyed_at"] = now
        node["key"] = None

        children = node.get("children", ())
        for child_id in reversed(children):
            if child_id not in seen:
                stack.append(child_id)

    return {"destroyed": destroyed, "count": len(destroyed), "at": now}


def is_destroyed(tree: dict, node_id: str) -> bool:
    """Return True when a node or any of its ancestors is destroyed.

    A destroyed ancestor makes all reachable descendants destroyed even when
    their own ``destroyed`` flag was never set.  A missing node id raises
    KeyError.
    """
    nodes = tree["nodes"]
    current_id: str | None = node_id
    seen: set[str] = set()

    while current_id is not None:
        if current_id in seen:
            return False
        seen.add(current_id)

        node = nodes[current_id]
        if node.get("destroyed"):
            return True
        current_id = node.get("parent")

    return False


def decrypt_check(tree: dict, node_id: str, ciphertext: bytes) -> bool:
    """Authenticate an envelope with a node key and report decryptability.

    The envelope layout is ``tag (32 bytes) || plaintext`` with
    ``tag == HMAC-SHA256(key, plaintext).digest()``.  Return True only when
    the node is neither destroyed nor under a destroyed ancestor and the tag
    matches.  Malformed input returns False.
    """
    try:
        if is_destroyed(tree, node_id):
            return False
        key = tree["nodes"][node_id].get("key")
    except (KeyError, TypeError, AttributeError):
        return False

    return _envelope_authenticates(key, ciphertext)


def purge_cache(cache: dict, tree: dict) -> int:
    """Remove cached key material for destroyed nodes and their descendants.

    ``cache`` maps node ids to dictionaries shaped like::

        {
            "key": b"...",
            "source": {"parent_key": b"...", "index": 0},
        }

    The whole entry must be removed, including ``source``; deleting only
    ``key`` would let an attacker re-derive the same child key.  Return the
    number of removed entries.  Entries for unknown nodes are left alone.
    """
    nodes = tree.get("nodes", {})
    removed = 0

    for cached_node_id in list(cache):
        if cached_node_id not in nodes:
            continue
        if is_destroyed(tree, cached_node_id):
            del cache[cached_node_id]
            removed += 1

    return removed


def verify_no_residual(tree: dict, backups: list[dict]) -> list:
    """Return ids of backups that still decrypt data of destroyed nodes.

    Each backup dictionary has ``id``, ``node_id``, ``key_snapshot`` (bytes),
    ``ciphertext`` (bytes) and ``filename``.  A backup is residual when its
    node is destroyed or under a destroyed ancestor and its ciphertext
    authenticates under ``key_snapshot``.  Filenames are metadata and must
    not influence the decision.  Results follow the input order.
    """
    residual_ids: list = []

    for backup in backups:
        node_id = backup.get("node_id")
        try:
            destroyed = is_destroyed(tree, node_id)
        except (KeyError, TypeError):
            continue

        if not destroyed:
            continue

        if _envelope_authenticates(backup.get("key_snapshot"), backup.get("ciphertext")):
            residual_ids.append(backup.get("id"))

    return residual_ids


def shred_batch(requests: list[dict], policy: dict, now: Any) -> dict:
    """Destroy one node per request without leaking state between requests.

    Each request is ``{"tree": <tree-dict>, "node_id": <id>}``.  Each tree is
    processed independently, even when different trees reuse the same node
    ids.  ``policy`` is a batch-options mapping; the current tests pass an
    empty mapping.  Return ``{"results": [<destroy-result>, ...]}`` in request
    order.
    """
    del policy  # No batch options are defined by the current contract.

    results = [destroy(request["tree"], request["node_id"], now) for request in requests]
    return {"results": results}
