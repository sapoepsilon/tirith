"""Data models matching CONTRACT.md (v1)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
Category = Literal["sast", "secret", "dependency", "dast", "config"]
FindingStatus = Literal["open", "validated", "not_reproduced", "fixing", "fixed"]
# The one definition of "open" (everything not closed). Posture counts and GET /findings?status=<these>
# use the same tuple, so the two can never disagree; CLOSED = fixed + not_reproduced.
OPEN_STATUSES: tuple[str, ...] = ("open", "validated", "fixing")
CLOSED_STATUSES: tuple[str, ...] = ("fixed", "not_reproduced")
ToolName = Literal["semgrep", "gitleaks", "trivy", "zap", "nmap", "nikto"]
TOOLS: tuple[str, ...] = ("semgrep", "gitleaks", "trivy", "zap", "nmap", "nikto")
ToolStatus = Literal["pending", "running", "done", "failed", "skipped"]
ScanStatus = Literal["queued", "running", "done", "failed"]
AssetKind = Literal["github_repo", "local_path", "url", "host"]
Mode = Literal["observe", "assisted", "autonomous"]
EventLevel = Literal["info", "warn", "error", "success"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def zero_counts() -> dict[str, int]:
    return {s: 0 for s in SEVERITIES}


def severity_counts(findings) -> dict[str, int]:
    """Tally findings by severity (all five keys present)."""
    out = zero_counts()
    for f in findings:
        out[f.severity] += 1
    return out


class AssetProfile(BaseModel):
    """What part of an asset matters. Globs are fnmatch patterns on repo-relative paths.

    focus:    the main app. Findings elsewhere are kept but de-ranked ("periphery").
    exclude:  findings under these paths are dropped entirely.
    sub_apps: directories that are separate, lower-priority lab sub-apps (tagged `lab-subapp`,
              component = the matching directory, still visible).
    Empty lists on an asset fall back to the matching `asset_profiles` entry in scope.yaml.
    """

    focus: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    sub_apps: list[str] = Field(default_factory=list)


class Asset(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ast"))
    kind: AssetKind
    ref: str
    name: str
    created_at: str = Field(default_factory=now_iso)
    focus: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    sub_apps: list[str] = Field(default_factory=list)


class AssetCreate(BaseModel):
    kind: AssetKind
    ref: str
    name: str | None = None
    focus: list[str] | None = None
    exclude: list[str] | None = None
    sub_apps: list[str] | None = None


class AssetUpdate(BaseModel):
    name: str | None = None
    focus: list[str] | None = None
    exclude: list[str] | None = None
    sub_apps: list[str] | None = None


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: new_id("scn"))
    asset_id: str
    status: ScanStatus = "queued"
    tools: dict[str, ToolStatus] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=zero_counts)
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None


class ScanCreate(BaseModel):
    asset_id: str
    tools: list[ToolName] | None = None


class Evidence(BaseModel):
    kind: Literal["request", "response", "log", "note"]
    label: str
    content: str


class Validation(BaseModel):
    id: str = Field(default_factory=lambda: new_id("val"))
    finding_id: str
    check: str
    result: Literal["confirmed", "not_reproduced", "unsupported", "error"]
    confidence: float = 0.0
    evidence: list[Evidence] = Field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None


class Advisory(BaseModel):
    """One advisory inside a grouped dependency finding."""

    id: str
    severity: Severity
    title: str = ""
    fixed_version: str | None = None
    url: str | None = None
    cwe: str | None = None


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: new_id("fnd"))
    scan_id: str
    asset_id: str
    fingerprint: str
    tool: ToolName
    rule_id: str
    title: str
    description: str = ""
    severity: Severity
    category: Category
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    cwe: str | None = None
    cve: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    url: str | None = None
    status: FindingStatus = "open"
    confidence: float = 0.5
    ai_summary: str | None = None
    validation: Validation | None = None
    fix_id: str | None = None
    # Signal-over-noise extensions (CONTRACT v1.1)
    advisories: list[Advisory] = Field(default_factory=list)  # grouped dependency findings: every CVE/GHSA
    component: str = "main"  # "main" | "periphery" | "lab:<dir>" (lab sub-app)
    tags: list[str] = Field(default_factory=list)  # e.g. "lab-subapp", "periphery", "test-path"
    priority: float = 0.0  # 0..100 = severity x confidence x reachability x validated; default sort key


class FixVerification(BaseModel):
    tests_passed: bool | None = None
    validation_result: str | None = None
    details: str | None = None


class Fix(BaseModel):
    id: str = Field(default_factory=lambda: new_id("fix"))
    finding_id: str
    mode: Mode
    status: Literal[
        "proposed", "pr_opened", "verified", "applied", "rolled_back", "failed", "escalated"
    ] = "proposed"
    diff: str = ""
    branch: str | None = None
    pr_url: str | None = None
    verification: FixVerification = Field(default_factory=FixVerification)
    created_at: str = Field(default_factory=now_iso)


class PostureHistoryPoint(BaseModel):
    ts: str
    score: int


class TopAction(BaseModel):
    """One plain-language fix covering one or more open findings (CONTRACT: Posture.top_actions)."""
    title: str
    why: str
    action: str
    finding_ids: list[str]
    severity: Severity
    fixable: bool = False


class Posture(BaseModel):
    asset_id: str | None
    score: int
    grade: Literal["A", "B", "C", "D", "F"]
    counts: dict[str, int]
    open: int
    fixed: int
    history: list[PostureHistoryPoint] = Field(default_factory=list)
    # v1.1: priority-weighted risk. counts/open cover everything; main_* cover the focused app only.
    risk: float = 0.0  # open weighted risk (lower is better)
    risk_fixed: float = 0.0  # weighted risk already closed by fixes
    main_counts: dict[str, int] = Field(default_factory=zero_counts)
    lab_open: int = 0
    top_actions: list[TopAction] = Field(default_factory=list)  # v1.4: up to 3 plain-language fixes


class ModePatch(BaseModel):
    """PATCH /mode body: both fields optional so a mode switch never drops the category list."""
    mode: Literal["observe", "assisted", "autonomous"] | None = None
    autonomous_categories: list[Literal["dependency_bump"]] | None = None


class ModeSettings(BaseModel):
    mode: Mode = "observe"
    autonomous_categories: list[str] = Field(default_factory=lambda: ["dependency_bump"])
    transient: bool = False  # set by a run that lifted the mode itself (restored after the run)


class Event(BaseModel):
    ts: str = Field(default_factory=now_iso)
    type: str
    level: EventLevel = "info"
    message: str
    scan_id: str | None = None
    finding_id: str | None = None
    fix_id: str | None = None
    data: dict[str, Any] | None = None


class AuditEntry(BaseModel):
    id: int | None = None
    ts: str = Field(default_factory=now_iso)
    actor: str = "system"
    action: str
    target: str | None = None
    allowed: bool = True
    details: dict[str, Any] | None = None
