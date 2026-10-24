"""Tirith remediation: explain, evidence-based validation, lab, fix -> PR -> verify -> merge/rollback.

Wiring (main.py):
    from .remediation import install
    install(app)            # mounts the router under /api and hooks the lab into the ZAP runner
"""

from __future__ import annotations


def install(app, prefix: str = "/api") -> None:
    from ..scanners import tools as scanner_tools
    from . import lab
    from .router import router

    app.include_router(router, prefix=prefix)
    scanner_tools.get_lab_target = lab.get_lab_target  # the runner looks this up at call time
    scanner_tools.get_lab_session = lab.session  # signed-in lab test user for ZAP
    scanner_tools.get_lab_seeds = lab.crawl_seeds  # JS-linked pages ZAP's spider would miss
