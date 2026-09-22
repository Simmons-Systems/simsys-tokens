"""Drop-in API-token store, auth and management surface for in-house web apps."""

from .core import Limits, authenticate
from .errors import TokenError
from .events import Emitter
from .events import set_sink as set_event_sink
from .models import SessionIdentity, TokenInfo

__version__ = "0.2.0"


def install_tokens(app, **kwargs):
    """Mount the management surface. Dispatches on the app object's framework.

    Prefers isinstance (survives subclasses and app factories); falls back to
    the module prefix for proxies/wrappers that hide the class. An explicit
    framework="fastapi" | "flask" overrides both.
    """
    framework = kwargs.pop("framework", None)
    if framework in ("fastapi", "flask"):
        from . import fastapi as _fa
        from . import flask as _fl

        return (_fa if framework == "fastapi" else _fl).install_tokens(app, **kwargs)
    if framework is not None:
        raise TypeError(f"unsupported framework={framework!r}; expected 'fastapi' or 'flask'")
    try:
        from fastapi.applications import FastAPI as _FastAPI

        if isinstance(app, _FastAPI):
            from .fastapi import install_tokens as _install

            return _install(app, **kwargs)
    except ImportError:
        pass
    try:
        from flask import Flask as _Flask

        if isinstance(app, _Flask):
            from .flask import install_tokens as _install

            return _install(app, **kwargs)
    except ImportError:
        pass
    # Fallback for wrapped/proxied apps that hide the class, then hard fail.
    # Never fall through to an adapter by default: a Starlette or other
    # ASGI app routed to the Flask adapter dies with an opaque
    # AttributeError deep inside a decorator.
    module = app.__class__.__module__
    if module.startswith("fastapi"):
        from .fastapi import install_tokens as _install

        return _install(app, **kwargs)
    if module.startswith("flask"):
        from .flask import install_tokens as _install

        return _install(app, **kwargs)
    raise TypeError(
        f"unsupported app type {module}.{app.__class__.__name__}; "
        f"simsys-tokens supports FastAPI and Flask. For another framework, "
        f"build on simsys_tokens.core.Endpoints directly."
    )


__all__ = [
    "__version__",
    "authenticate",
    "install_tokens",
    "set_event_sink",
    "Emitter",
    "Limits",
    "SessionIdentity",
    "TokenInfo",
    "TokenError",
]
