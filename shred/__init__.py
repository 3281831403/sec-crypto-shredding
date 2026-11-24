"""Shred package facade."""

from .api import (
    build_tree,
    decrypt_check,
    derive_child,
    destroy,
    is_destroyed,
    purge_cache,
    shred_batch,
    verify_no_residual,
)

__all__ = [
    "build_tree",
    "derive_child",
    "destroy",
    "is_destroyed",
    "decrypt_check",
    "purge_cache",
    "verify_no_residual",
    "shred_batch",
]