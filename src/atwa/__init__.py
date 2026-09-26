from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("atwa")
except PackageNotFoundError:  # not installed (e.g. running straight from source) -- best-effort fallback
    __version__ = "0.0.0-dev"
