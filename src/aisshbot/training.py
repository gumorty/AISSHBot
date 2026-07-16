"""Pure, dependency-free analysis for read-only training artifacts.

The gateway is responsible for collecting bounded text.  This module only
interprets that text, so it never opens a server path and never executes a
command.  That separation keeps training analysis testable and prevents a
future parser from bypassing the path policy.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TrainingAnalysis:
    framework: str = "unknown"
    current_epoch: int | None = None
    total_epochs: int | None = None
    progress_percent: float | None = None
    latest_metrics: dict[str, str] = field(default_factory=dict)
    best_epoch: int | None = None
    best_metrics: dict[str, str] = field(default_factory=dict)
    trend: str = "insufficient_data"
    status: str = "UNKNOWN"
    error_count: int = 0
    last_update: str | None = None


def _number(value: str | None) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _int(value: str | None) -> int | None:
    number = _number(value)
    return int(number) if number is not None else None


def _column(row: dict[str, str], *names: str) -> str | None:
    normalized = {key.strip().lower(): value.strip() for key, value in row.items()}
    for name in names:
        value = normalized.get(name.lower())
        if value not in (None, ""):
            return value
    return None


def _metric_view(row: dict[str, str]) -> dict[str, str]:
    aliases = (
        ("box_loss", "train/box_loss", "train/box loss"),
        ("cls_loss", "train/cls_loss", "train/cls loss"),
        ("map50", "metrics/map50(b)", "metrics/map50", "map50"),
        ("map5095", "metrics/map50-95(b)", "metrics/map50-95", "map50-95"),
        ("precision", "metrics/precision(b)", "metrics/precision", "precision"),
        ("recall", "metrics/recall(b)", "metrics/recall", "recall"),
    )
    result: dict[str, str] = {}
    for label, *names in aliases:
        value = _column(row, *names)
        if value is not None:
            result[label] = value
    return result


def analyze_results_csv(
    content: str,
    *,
    total_epochs: int | None = None,
    process_alive: bool = False,
    done_marker: bool = False,
    error_count: int = 0,
    last_update: str | None = None,
) -> TrainingAnalysis:
    """Analyze a bounded YOLO-like results CSV.

    The parser accepts the full header plus a bounded tail.  It does not rely
    on the header being in the last N lines, which fixes the old tail-only
    parser.  Unknown columns are ignored while known metric aliases are kept.
    """
    rows = list(csv.DictReader(io.StringIO(content)))
    rows = [row for row in rows if _int(_column(row, "epoch")) is not None]
    if not rows:
        status = "RUNNING" if process_alive else "UNKNOWN"
        return TrainingAnalysis(status=status, error_count=error_count, last_update=last_update)

    epochs = [_int(_column(row, "epoch")) for row in rows]
    current_epoch = epochs[-1]
    if total_epochs is None:
        total_epochs = _int(_column(rows[-1], "epochs", "total_epochs"))
    progress = None
    if current_epoch is not None and total_epochs and total_epochs > 0:
        progress = min(100.0, max(0.0, current_epoch / total_epochs * 100))

    latest_metrics = _metric_view(rows[-1])
    score_name = "map5095" if any("map5095" in _metric_view(row) for row in rows) else "map50"
    scored = [(index, _number(_metric_view(row).get(score_name))) for index, row in enumerate(rows)]
    scored = [(index, score) for index, score in scored if score is not None]
    best_epoch = None
    best_metrics: dict[str, str] = {}
    if scored:
        best_index = max(scored, key=lambda item: item[1])[0]
        best_epoch = epochs[best_index]
        best_metrics = _metric_view(rows[best_index])

    recent = rows[-10:]
    score_values = [_number(_metric_view(row).get(score_name)) for row in recent]
    score_values = [value for value in score_values if value is not None]
    loss_values = [_number(_metric_view(row).get("box_loss")) for row in recent]
    loss_values = [value for value in loss_values if value is not None]
    trend = "insufficient_data"
    if len(score_values) >= 2:
        score_delta = score_values[-1] - score_values[0]
        loss_delta = loss_values[-1] - loss_values[0] if len(loss_values) >= 2 else 0.0
        if score_delta > 0.002 and loss_delta <= 0.01:
            trend = "improving"
        elif score_delta < -0.002:
            trend = "declining"
        else:
            trend = "plateau"

    if process_alive:
        status = "RUNNING"
    elif done_marker or (total_epochs is not None and current_epoch is not None and current_epoch >= total_epochs):
        status = "COMPLETED"
    elif error_count:
        status = "FAILED"
    else:
        status = "UNKNOWN"

    framework = "ultralytics" if any(
        key in {key.strip().lower() for key in rows[0]}
        for key in ("metrics/map50(b)", "train/box_loss")
    ) else "generic_csv"
    return TrainingAnalysis(
        framework=framework,
        current_epoch=current_epoch,
        total_epochs=total_epochs,
        progress_percent=progress,
        latest_metrics=latest_metrics,
        best_epoch=best_epoch,
        best_metrics=best_metrics,
        trend=trend,
        status=status,
        error_count=error_count,
        last_update=last_update,
    )


def total_epochs_from_text(content: str) -> int | None:
    """Extract an epoch limit from a small args/config text fragment."""
    patterns = (
        r"(?im)^\s*epochs\s*:\s*(\d+)",
        r"(?i)[\"']epochs[\"']\s*[:=]\s*(\d+)",
        r"(?i)(?:--epochs|epochs\s*=)\s*(\d+)",
    )
    for pattern in patterns:
        match = re.search(pattern, content or "")
        if match:
            return int(match.group(1))
    return None


def summarize_status(analysis: TrainingAnalysis) -> str:
    labels = {
        "RUNNING": "正在训练",
        "COMPLETED": "已完成",
        "FAILED": "异常退出",
        "STALE": "长时间无更新",
        "PENDING": "等待开始",
        "UNKNOWN": "暂时无法确认",
    }
    return labels.get(analysis.status, analysis.status)
