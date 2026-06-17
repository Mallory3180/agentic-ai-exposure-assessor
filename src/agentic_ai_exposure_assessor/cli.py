"""Command line interface (Typer).

Commands: ``init-fixtures``, ``ingest-config``, ``ingest-otlp``, ``assess``,
``export-report`` and ``serve``. Console output is intentionally ASCII-only so it renders
correctly on Windows consoles using legacy code pages (e.g. cp932).
"""

from __future__ import annotations

from pathlib import Path

import typer

from . import (
    config_loader,
    db,
    fixture_templates,
    report,
    risk_engine,
    trace_adapters,
    trace_ingest,
)
from . import targets as targets_mod

app = typer.Typer(
    add_completion=False,
    help="Agentic AI Exposure Assessor - defensive inventory + runtime trace risk assessment.",
)


def _echo(message: str) -> None:
    typer.echo(message)


@app.command("init-fixtures")
def init_fixtures(
    output: Path = typer.Option(Path("fixtures"), "--output", "-o", help="Target directory."),
    overwrite: bool = typer.Option(True, "--overwrite/--no-overwrite"),
) -> None:
    """Generate the sample fixture files (YAML + trace JSON)."""
    written = fixture_templates.write_fixtures(output, overwrite=overwrite)
    _echo(f"Wrote {len(written)} fixture file(s) to {output}")
    for path in written:
        _echo(f"  - {path}")


@app.command("ingest-config")
def ingest_config(
    fixtures: Path = typer.Option(Path("fixtures"), "--fixtures", "-f", help="Fixtures dir."),
) -> None:
    """Load inventory YAML (agents/tools/permissions/...) into the database."""
    db.init_db()
    try:
        with db.session_scope() as session:
            counts = config_loader.load_directory(fixtures, session)
    except config_loader.ConfigError as exc:
        _echo(f"ERROR: {exc}")
        raise typer.Exit(code=1) from exc
    total = sum(counts.values())
    _echo(f"Ingested {total} inventory record(s) from {fixtures}:")
    for name, count in counts.items():
        _echo(f"  - {name}: {count}")


@app.command("ingest-otlp")
def ingest_otlp(
    file: Path = typer.Option(..., "--file", help="Exported trace/telemetry file."),
    format: str = typer.Option(
        "auto",
        "--format",
        help="Telemetry format: auto | otlp | jaeger | langsmith | simplified.",
    ),
    append: bool = typer.Option(False, "--append", help="Keep existing runtime data."),
) -> None:
    """Load exported telemetry and normalize it into the database.

    Supports native OTLP/JSON (incl. OTel Collector 'file' exporter / NDJSON), Jaeger query
    JSON, and LangSmith run exports. Use --format to override auto-detection.
    """
    db.init_db()
    try:
        trace = trace_adapters.load_trace_any(file, fmt=format)
        with db.session_scope() as session:
            counts = trace_ingest.persist(trace, session, replace=not append)
    except trace_ingest.TraceIngestError as exc:
        _echo(f"ERROR: {exc}")
        raise typer.Exit(code=1) from exc
    _echo(f"Ingested trace from {file} (format={format}):")
    for name, count in counts.items():
        _echo(f"  - {name}: {count}")


@app.command("ingest-live")
def ingest_live(
    targets: Path = typer.Option(
        ..., "--targets", "-t", help="Targets YAML (see targets.example.yml)."
    ),
    append: bool = typer.Option(False, "--append", help="Merge with existing inventory."),
) -> None:
    """Pull inventory from live target platforms declared in a targets file.

    Reads connection info from the targets file and credentials from environment variables
    (never stored in the file). Runtime traces are collected separately via the OTLP
    receiver exposed by 'serve' (POST /v1/traces).
    """
    db.init_db()
    try:
        target_list = targets_mod.load_targets(targets)
    except targets_mod.TargetsError as exc:
        _echo(f"ERROR: {exc}")
        raise typer.Exit(code=1) from exc
    with db.session_scope() as session:
        result = targets_mod.pull_inventory(target_list, session, replace=not append)
    _echo("Per-target result:")
    for target_id, status in result["targets"].items():
        _echo(f"  - {target_id}: {status}")
    total = sum(result["counts"].values())
    _echo(f"Persisted {total} inventory record(s):")
    for name, count in result["counts"].items():
        _echo(f"  - {name}: {count}")


@app.command("assess")
def assess(
    name: str = typer.Option("", "--name", help="Optional run name."),
    fixtures: Path = typer.Option(Path("fixtures"), "--fixtures", help="Config source label."),
    trace: Path = typer.Option(
        Path("fixtures") / "otlp_trace_sample.json", "--trace", help="Trace source label."
    ),
) -> None:
    """Run the OWASP Agentic rule engine and persist findings."""
    db.init_db()
    with db.session_scope() as session:
        run = risk_engine.assess(
            session,
            run_name=name or None,
            config_sources=[str(fixtures)],
            trace_sources=[str(trace)],
        )
        _echo(f"Assessment '{run.name}' complete.")
        _echo(f"  Agents: {run.total_agents}  Tools: {run.total_tools}")
        _echo(f"  Findings: {run.total_findings}  Aggregate risk score: {run.risk_score}")
        _echo("  Findings by OWASP category:")
        for code, count in sorted(run.owasp_counts.items()):
            _echo(f"    - {code}: {count}")


@app.command("export-report")
def export_report(
    format: str = typer.Option("markdown", "--format", help="json | markdown | html."),
    output: Path = typer.Option(Path("reports") / "report.md", "--output", "-o"),
) -> None:
    """Export the latest assessment as JSON, Markdown or HTML."""
    db.init_db()
    try:
        with db.session_scope() as session:
            path = report.export(session, format, output)
    except ValueError as exc:
        _echo(f"ERROR: {exc}")
        raise typer.Exit(code=1) from exc
    _echo(f"Report written to {path}")


@app.command("reset-db")
def reset_database() -> None:
    """Drop and recreate all tables (clears inventory, traces and findings)."""
    db.reset_db()
    _echo(f"Database reset at {db.get_db_path()}")


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(False, "--reload/--no-reload"),
) -> None:
    """Start the FastAPI web UI (Uvicorn)."""
    import uvicorn

    db.init_db()
    _echo(f"Starting web UI at http://{host}:{port} (Ctrl+C to stop)")
    _echo(f"OTLP/HTTP trace receiver listening at http://{host}:{port}/v1/traces")
    uvicorn.run(
        "agentic_ai_exposure_assessor.app:app",
        host=host,
        port=port,
        reload=reload,
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
