"""Domain model for associating processes, runs, metrics and artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .training import TrainingAnalysis


@dataclass(frozen=True)
class TrainingTask:
    server_id: str
    task_id: str
    process_group: str | None = None
    pids: tuple[str, ...] = ()
    gpu_ids: tuple[str, ...] = ()
    runner_script: str | None = None
    command_summary: str | None = None
    work_dir: str | None = None
    run_dir: str | None = None
    framework: str = "unknown"
    status: str = "UNKNOWN"
    current_epoch: int | None = None
    total_epochs: int | None = None
    progress: float | None = None
    latest_metrics: dict[str, str] = field(default_factory=dict)
    best_metrics: dict[str, str] = field(default_factory=dict)
    best_epoch: int | None = None
    artifacts: tuple[dict[str, Any], ...] = ()
    update_time: str | None = None
    stale_seconds: int | None = None
    evidence: tuple[str, ...] = ()

    @classmethod
    def from_analysis(
        cls,
        analysis: TrainingAnalysis,
        *,
        server_id: str,
        task_id: str,
        run_dir: str | None = None,
        work_dir: str | None = None,
        pids: Iterable[str] = (),
        gpu_ids: Iterable[str] = (),
        artifacts: Iterable[dict[str, Any]] = (),
        evidence: Iterable[str] = (),
    ) -> "TrainingTask":
        return cls(
            server_id=server_id,
            task_id=task_id,
            pids=tuple(str(pid) for pid in pids),
            gpu_ids=tuple(str(gpu) for gpu in gpu_ids),
            work_dir=work_dir,
            run_dir=run_dir,
            framework=analysis.framework,
            status=analysis.status,
            current_epoch=analysis.current_epoch,
            total_epochs=analysis.total_epochs,
            progress=analysis.progress_percent,
            latest_metrics=dict(analysis.latest_metrics),
            best_metrics=dict(analysis.best_metrics),
            best_epoch=analysis.best_epoch,
            artifacts=tuple(dict(item) for item in artifacts),
            update_time=analysis.last_update,
            evidence=tuple(evidence),
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify_training_status(
    *,
    process_alive: bool,
    analysis: TrainingAnalysis,
    last_update: datetime | None = None,
    stale_after_seconds: int = 900,
    now: datetime | None = None,
) -> str:
    """Combine process state, completion and update freshness conservatively."""
    if process_alive and last_update is not None:
        current = now or datetime.now(timezone.utc)
        observed = last_update if last_update.tzinfo else last_update.replace(tzinfo=timezone.utc)
        if (current - observed).total_seconds() > stale_after_seconds:
            return "STALE"
    if process_alive:
        return "RUNNING"
    if analysis.status == "COMPLETED":
        return "COMPLETED"
    if analysis.error_count:
        return "FAILED"
    return analysis.status
