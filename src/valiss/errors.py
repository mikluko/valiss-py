"""Error type shared by every valiss module."""


class ValissError(Exception):
    """Any authentication, encoding, or credential failure.

    Messages are prefixed ``valiss:`` to match the Go implementation.
    """
