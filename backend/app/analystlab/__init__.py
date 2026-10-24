"""Analyst-lab: the bounded, scope-checked analyst demo (see CONTRACT.md "Analyst lab (v1.4)").

  - `lab`        known Docker lab handles (the only destinations that may be contacted)
  - `http`       the single raw read-only request client (no redirects, no proxy, no DNS)
  - `tools`      the two model-facing tool actions, schema-checked and budgeted
  - `loop`       the ReAct loop (DeepSeek via remediation.llm), plain runner and linear demo scenario
  - `regression` the access-control check on the demo target and the demo asset/finding
"""

from . import demo, lab, loop, regression, tools  # noqa: F401

__all__ = ["demo", "lab", "loop", "regression", "tools"]