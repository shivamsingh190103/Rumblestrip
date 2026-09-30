class RumblestripError(Exception):
    """Expected user-facing error."""


class ConfigError(RumblestripError):
    """A project configuration or rule file is invalid."""


class IntegrityError(RumblestripError):
    """An approved rule has been modified without reapproval."""


class ToolError(RumblestripError):
    """A deterministic engine failed."""
