"""Shared TLS context for outbound HTTPS calls."""
from __future__ import annotations

import ssl

import certifi


def https_context() -> ssl.SSLContext:
    # A PyInstaller-frozen interpreter on macOS has no usable system CA store,
    # so every HTTPS call must verify against certifi's bundled roots.
    return ssl.create_default_context(cafile=certifi.where())
