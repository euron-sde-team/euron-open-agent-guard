"""The AgentGuard sandbox service: the only process that runs untrusted code.

The API and the worker never execute code an agent submits. They post it to this service
(its own unprivileged image on an internal network), which runs each program in a fresh
nsjail built from user namespaces, bounds it with rlimits, a wall clock and output caps,
and measures it exactly. See ``docs/architecture/sandbox.md``.

This package depends only on FastAPI, uvicorn and pydantic, never on ``agentguard``, so
the sandbox image carries none of the API's code, libraries or credentials.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
