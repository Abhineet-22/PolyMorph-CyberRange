"""
PolyMorph CLI
=============
Entry point for the command-line interface.

Usage examples
--------------
  # Auto-select strategy (PDF + ZIP):
  python -m polymorph build document.pdf archive.zip -A pdf -B zip -o out.pdf

  # Force a specific strategy:
  python -m polymorph build doc.pdf arc.zip -A pdf -B zip -s append -o out.pdf

  # List viable strategies for a pair without building:
  python -m polymorph info -A pdf -B zip

  # List all registered formats:
  python -m polymorph formats
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure UTF-8 output on Windows to prevent UnicodeEncodeError on box characters
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .core.constructor import Constructor
from .core.format_registry import FormatRegistry
from .probe.probe_engine import ProbeEngine
from .probe.probe_result import Confidence
from .probe.target_scanner import TargetScanner, ScanOptions

console = Console(legacy_windows=False)


# ─────────────────────────────────────────────────────────────────────────────
# CLI group
# ─────────────────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """PolyMorph — Polyglot file construction framework."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# build command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("file_a", type=click.Path(exists=True, path_type=Path))
@click.argument("file_b", type=click.Path(exists=True, path_type=Path))
@click.option("-A", "--fmt-a", required=True, help="Format name for FILE_A (e.g. pdf)")
@click.option("-B", "--fmt-b", required=True, help="Format name for FILE_B (e.g. zip)")
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None,
              help="Output file path. Defaults to <FILE_A_stem>.polyglot.<ext>")
@click.option("-s", "--strategy", default=None,
              help="Force a specific strategy: append | prepend | inject | nest")
@click.option("--skip-validation", is_flag=True, default=False,
              help="Skip post-construction format validation.")
def build(
    file_a: Path,
    file_b: Path,
    fmt_a: str,
    fmt_b: str,
    output: Path | None,
    strategy: str | None,
    skip_validation: bool,
) -> None:
    """
    Build a polyglot file from FILE_A (host) and FILE_B (payload).

    The output is simultaneously valid as both FMT_A and FMT_B.
    """

    console.rule("[bold magenta]PolyMorph[/] — Build")

    # ── Construct ─────────────────────────────────────────────────────
    with console.status("Constructing polyglot…"):
        result = Constructor.build(
            file_a=file_a,
            file_b=file_b,
            fmt_a=fmt_a.lower(),
            fmt_b=fmt_b.lower(),
            force_strategy=strategy,
            skip_validation=skip_validation,
        )

    # ── Render result ─────────────────────────────────────────────────
    if not result.success:
        console.print(
            Panel(
                f"[bold red]FAILED[/]\n\n{result.error}",
                title="Construction Error",
                border_style="red",
            )
        )
        sys.exit(1)

    # Build summary table.
    t = Table(show_header=False, border_style="bold magenta")
    t.add_column("Field", style="bold cyan")
    t.add_column("Value")
    t.add_row("Formats",   f"{result.fmt_a.upper()} + {result.fmt_b.upper()}")
    t.add_row("Strategy",  result.strategy)
    t.add_row("Size",      f"{result.size_bytes:,} bytes")
    t.add_row("SHA-256",   result.sha256)

    if result.validation_a:
        icon = "✓" if result.validation_a.valid else "✗"
        colour = "green" if result.validation_a.valid else "red"
        t.add_row(
            f"Valid as {result.fmt_a.upper()}",
            f"[{colour}]{icon}[/]  {result.validation_a.detail}",
        )

    if result.validation_b:
        icon = "✓" if result.validation_b.valid else "✗"
        colour = "green" if result.validation_b.valid else "red"
        t.add_row(
            f"Valid as {result.fmt_b.upper()}",
            f"[{colour}]{icon}[/]  {result.validation_b.detail}",
        )

    if result.notes:
        t.add_row("Notes", result.notes)

    console.print(t)

    # Dual-validity verdict.
    if not skip_validation:
        if result.both_valid:
            console.print(
                "\n[bold green]✓ Polyglot is valid in both formats.[/]"
            )
        else:
            console.print(
                "\n[bold yellow]⚠  One or more format validations failed. "
                "Check details above.[/]"
            )

    # ── Write output ──────────────────────────────────────────────────
    if output is None:
        ext = f".polyglot.{fmt_a}"
        output = file_a.with_suffix(ext)

    output.write_bytes(result.data)
    console.print(f"\nOutput written to [bold]{output}[/]")


# ─────────────────────────────────────────────────────────────────────────────
# info command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("-A", "--fmt-a", required=True, help="Host format name")
@click.option("-B", "--fmt-b", required=True, help="Payload format name")
def info(fmt_a: str, fmt_b: str) -> None:
    """Show viable strategies for a format pair without building anything."""
    try:
        description = FormatRegistry.describe_pair(fmt_a.lower(), fmt_b.lower())
        console.print(
            Panel(description, title="Pair Analysis", border_style="cyan")
        )
    except KeyError as exc:
        console.print(f"[red]{exc}[/]")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# formats command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command("formats")
def list_formats() -> None:
    """List all registered formats and their key properties."""
    t = Table(title="Registered Formats", border_style="bold magenta")
    t.add_column("Name",         style="bold cyan")
    t.add_column("Extensions")
    t.add_column("Append-tol.")
    t.add_column("Prepend-tol.")
    t.add_column("Scans-end")
    t.add_column("Comment field")
    t.add_column("Validator")

    for name in FormatRegistry.all_names():
        s = FormatRegistry.get(name)
        t.add_row(
            name,
            " ".join(s.extensions),
            "[green]✓[/]" if s.append_tolerant  else "[dim]—[/]",
            "[green]✓[/]" if s.prepend_tolerant else "[dim]—[/]",
            "[green]✓[/]" if s.scans_from_end   else "[dim]—[/]",
            (
                f"[green]✓[/] ({s.comment_max_bytes or '∞'} B)"
                if s.has_comment_field else "[dim]—[/]"
            ),
            s.validator or "—",
        )

    console.print(t)


# ─────────────────────────────────────────────────────────────────────────────
# probe command
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("-f", "--fmt",    required=True,
              help="Format name to probe (registered e.g. 'pdf', or new e.g. 'elf').")
@click.option("-s", "--sample", required=True,
              type=click.Path(exists=True, path_type=Path),
              help="Path to a sample file of this format.")
@click.option("--validator-cmd", default=None,
              help=(
                  "Shell command to validate the format. "
                  "Use {file} as placeholder for the temp file path. "
                  "Exit code 0 = valid. "
                  "Example: 'readelf -h {file}'"
              ))
@click.option("--magic-bytes", default=None,
              help=(
                  "Hex string of magic bytes for unknown formats. "
                  "Used as a fallback validator when --validator-cmd is absent. "
                  "Example: 7f454c46 for ELF"
              ))
@click.option("--update", is_flag=True, default=False,
              help="Write measured values back to the registry if confidence >= MEDIUM.")
@click.option("--suggest", is_flag=True, default=False,
              help=(
                  "Run the SuggestionEngine when no structural parser is found. "
                  "Queries DuckDuckGo and an available LLM for parser recommendations."
              ))
@click.option("--llm", default=None,
              help=(
                  "Preferred LLM provider for --suggest. "
                  "Values: ollama, lmstudio, anthropic, openai, gemini. "
                  "Falls back to auto-discovery if not set."
              ))
def probe(
    fmt: str,
    sample: Path,
    validator_cmd: str | None,
    magic_bytes: str | None,
    update: bool,
    suggest: bool,
    llm: str | None,
) -> None:
    """
    Empirically probe a format's parsing contract against a real sample file.

    VERIFICATION mode (format already registered):
      Measured values are compared against the registered FormatSpec.
      Divergences are highlighted.

    DISCOVERY mode (format not yet registered):
      Requires --validator-cmd or --magic-bytes to validate the format.
      Generates a FormatSpec template from probe results.
      Use --update to register the new format.

    Examples:

      python -m PolyMorph probe -f pdf -s document.pdf

      python -m PolyMorph probe -f elf -s binary.elf --magic-bytes 7f454c46

      python -m PolyMorph probe -f elf -s binary.elf \\
          --validator-cmd "readelf -h {file}" --update
    """

    console.rule(f"[bold magenta]PolyMorph[/] — Probe: {fmt.upper()}")

    # ── Build validator ───────────────────────────────────────────────
    explicit_validator = None
    magic_raw: bytes | None = None

    if validator_cmd:
        explicit_validator = ProbeEngine.make_cmd_validator(validator_cmd)
        console.print(f"[dim]Validator: shell command — {validator_cmd}[/]")

    if magic_bytes:
        try:
            magic_raw = bytes.fromhex(magic_bytes.replace(" ", ""))
            console.print(f"[dim]Magic bytes: {magic_raw.hex()} ({len(magic_raw)} bytes)[/]")
        except ValueError:
            console.print(f"[red]Invalid --magic-bytes value '{magic_bytes}'. "
                          f"Must be a hex string (e.g. 7f454c46).[/]")
            sys.exit(1)

    with console.status(f"Probing {fmt.upper()} with {sample.name}…"):
        report = ProbeEngine.run(
            fmt=fmt.lower(),
            sample_path=sample,
            validator=explicit_validator,
            magic_bytes=magic_raw,
            suggest=suggest,
            preferred_llm=llm,
        )

    # ── Header ────────────────────────────────────────────────────────
    mode_label = (
        "[cyan]VERIFICATION[/]"
        if report.mode == "verification"
        else "[yellow]DISCOVERY[/]"
    )
    valid_icon = "[green]✓[/]" if report.sample_valid else "[red]✗[/]"
    console.print(f"\nMode    : {mode_label}")
    console.print(
        f"Sample  : {report.sample_path} "
        f"({report.sample_size_bytes:,} bytes)  {valid_icon}"
    )

    # ── Detection info (discovery mode) ──────────────────────────────
    if report.detection:
        d = report.detection
        console.print(f"Detected: [bold]{d.description or 'unknown'}[/]")
        console.print(f"MIME    : {d.mime_type or '—'}")
        tier_colour = {1: "green", 2: "yellow", 3: "red"}.get(
            d.validator_tier, "white"
        )
        console.print(
            f"Validator: [{tier_colour}]Tier {d.validator_tier}[/] — "
            f"{d.validator_source}"
        )
        if not d.parser_available and d.install_hint:
            console.print(
                f"[yellow]⚠  Structural parser not installed.[/]\n"
                f"   {d.install_hint}"
            )

    if not report.sample_valid:
        console.print(Panel(
            f"[red]{report.error}[/]",
            title="Probe Aborted",
            border_style="red",
        ))
        sys.exit(1)

    # ── Append probe results ──────────────────────────────────────────
    if report.append_result:
        ar = report.append_result
        t = Table(
            title="Append Probe",
            show_header=True,
            border_style="bold magenta",
        )
        t.add_column("Probe size (bytes)")
        t.add_column("Parser accepted")
        t.add_column("Detail")

        for test in ar.tests:
            icon = "[green]✓[/]" if test.passed else "[red]✗[/]"
            t.add_row(str(test.probe_size), icon, test.detail[:80])

        console.print(t)

        _row = Table(show_header=False, border_style="cyan")
        _row.add_column("Field", style="bold cyan")
        _row.add_column("Value")
        _row.add_row("append_tolerant",        str(ar.append_tolerant))
        _row.add_row("checksum_covers_append",  str(ar.checksum_covers_append))
        _row.add_row("Confidence",              ar.confidence.value)
        _row.add_row("Notes",                   ar.notes)
        console.print(_row)

    # ── Prepend probe results ─────────────────────────────────────────
    if report.prepend_result:
        pr = report.prepend_result
        t = Table(
            title="Prepend Probe",
            show_header=True,
            border_style="bold magenta",
        )
        t.add_column("Probe size (bytes)")
        t.add_column("Parser accepted")
        t.add_column("Detail")

        for test in pr.tests:
            icon   = "[green]✓[/]" if test.passed else "[red]✗[/]"
            label  = f"{test.probe_size:>7}"
            detail = test.detail[:80] if test.detail else ""
            t.add_row(label, icon, detail)

        console.print(t)

        max_str = (
            "unlimited (-1)"
            if pr.max_prepend_bytes == -1
            else str(pr.max_prepend_bytes)
        )
        _row = Table(show_header=False, border_style="cyan")
        _row.add_column("Field", style="bold cyan")
        _row.add_column("Value")
        _row.add_row("prepend_tolerant",  str(pr.prepend_tolerant))
        _row.add_row("max_prepend_bytes", max_str)
        _row.add_row("Confidence",        pr.confidence.value)
        _row.add_row("Notes",             pr.notes)
        console.print(_row)

    # ── Verification mode: divergences ───────────────────────────────
    if report.mode == "verification":
        if report.divergences:
            console.print(
                "\n[bold yellow]⚠  Divergences from registered FormatSpec:[/]"
            )
            for div in report.divergences:
                console.print(
                    f"  [yellow]{div.field_name}[/]: "
                    f"registered=[red]{div.registered_value!r}[/] "
                    f"measured=[green]{div.measured_value!r}[/] "
                    f"[{div.confidence.value}]"
                )
        else:
            console.print(
                "\n[bold green]✓ All measured values match the registered FormatSpec.[/]"
            )

    # ── Discovery mode: FormatSpec template ───────────────────────────
    else:
        console.print(
            "\n[bold yellow]Discovery mode — FormatSpec template from probe results:[/]"
        )
        t = Table(show_header=False, border_style="yellow")
        t.add_column("Field", style="bold cyan")
        t.add_column("Measured value")
        t.add_column("Note")

        identity_fields = {
            "name":       "auto-filled",
            "extensions": "fill in manually  e.g. ('.elf',)",
            "mime_types": "fill in manually  e.g. ('application/x-elf',)",
            "magic_bytes":"from --magic-bytes" if magic_raw else "fill in manually",
        }
        for field, note in identity_fields.items():
            val = report.suggested_updates.get(field, "[dim]—[/]")
            t.add_row(field, str(val), f"[dim]{note}[/]")

        measured_fields = [
            "append_tolerant", "prepend_tolerant",
            "max_prepend_bytes", "checksum_covers_append",
        ]
        for field in measured_fields:
            val = report.suggested_updates.get(field, "[dim]not measured[/]")
            t.add_row(field, str(val), "[dim]probe-measured[/]")

        console.print(t)
        console.print(
            "[dim]Use --update to register this format with the measured values.[/]"
        )

    # ── Suggestion results ────────────────────────────────────────────
    if report.suggestion:
        sr = report.suggestion
        console.print("\n[bold yellow]SuggestionEngine Results[/]")

        if sr.web_results:
            console.print(f"\n[bold]Web Results[/] ({len(sr.web_results)} found):")
            for i, wr in enumerate(sr.web_results, 1):
                console.print(f"  {i}. [cyan]{wr.title}[/]")
                console.print(f"     {wr.url}")
                if wr.snippet:
                    console.print(f"     [dim]{wr.snippet[:120]}[/]")

        if sr.llm_suggestions:
            provider_label = f" via {sr.llm_provider}" if sr.llm_provider else ""
            console.print(f"\n[bold]LLM Suggestions[/]{provider_label}:")
            t = Table(show_header=True, border_style="cyan")
            t.add_column("Tool / Library", style="bold cyan")
            t.add_column("Type")
            t.add_column("Reliability")
            t.add_column("Install")
            t.add_column("Notes")
            for s in sr.llm_suggestions:
                rel_colour = {
                    "high": "green", "medium": "yellow", "low": "red"
                }.get(s.reliability, "white")
                t.add_row(
                    s.name,
                    s.type,
                    f"[{rel_colour}]{s.reliability}[/]",
                    s.install,
                    s.notes[:60],
                )
            console.print(t)

            # Print validator_cmd hints separately for easy copy-paste.
            console.print("\n[dim]Suggested --validator-cmd values:[/]")
            for s in sr.llm_suggestions:
                if s.validator_cmd:
                    console.print(f"  [dim]{s.name}:[/] {s.validator_cmd}")

        if sr.error:
            console.print(f"\n[dim]Suggestion engine note: {sr.error}[/]")

    elif suggest and report.detection and not report.detection.needs_suggestion:
        console.print(
            "\n[dim]--suggest: structural parser was found; "
            "SuggestionEngine not needed.[/]"
        )

    # ── Registry update ───────────────────────────────────────────────
    if update:
        if report.suggested_updates:
            updated = ProbeEngine.apply(report)
            if updated:
                action = (
                    "updated" if report.mode == "verification" else "registered"
                )
                console.print(
                    f"\n[bold green]✓ Format '{fmt}' {action} in registry "
                    f"(probe_verified=True).[/]\n"
                    f"Fields written: {list(report.suggested_updates.keys())}"
                )
        else:
            console.print(
                "\n[dim]No updates applied — no fields met the confidence threshold.[/]"
            )
    else:
        if report.suggested_updates:
            console.print(
                "\n[dim]Run with --update to write these values to the registry.[/]"
            )


# ─────────────────────────────────────────────────────────────────────────────
# scan command  — General-purpose web recon
# ─────────────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--url",   required=True, help="Target URL to scan (e.g. http://localhost:8081).")
@click.option("--depth", default=2,     show_default=True, help="BFS crawl depth.")
@click.option("--pages", default=50,    show_default=True, help="Max pages to crawl.")
@click.option("--timeout", default=10,  show_default=True, help="Per-request timeout (seconds).")
@click.option("--out",   default=None,  type=click.Path(path_type=Path),
              help="Save full JSON report to this file.")
@click.option("--no-probe", is_flag=True, default=False,
              help="Skip probing well-known discovery paths.")
@click.option("--no-verify", is_flag=True, default=False,
              help="Disable TLS verification (defaults to certifi CA bundle).")
def scan(
    url: str,
    depth: int,
    pages: int,
    timeout: int,
    out: Path | None,
    no_probe: bool,
    no_verify: bool,
) -> None:
    """
    Passive web reconnaissance: fingerprint, map, and recommend polyglot strategies.

    Example:

      python -m PolyMorph scan --url http://localhost:8081

      python -m PolyMorph scan --url https://target.example.com --depth 3 --out recon.json
    """
    console.rule("[bold magenta]PolyMorph[/] — Recon Scan")

    try:
        from .probe.target_scanner import TargetScanner, ScanOptions
    except ImportError as exc:
        console.print(f"[red]Import error: {exc}[/]")
        console.print("[dim]Install missing deps: pip install requests beautifulsoup4 certifi[/]")
        sys.exit(1)

    opts = ScanOptions(
        max_depth=depth,
        max_pages=pages,
        timeout=timeout,
        probe_common_paths=not no_probe,
        verify_tls=not no_verify,
    )
    scanner = TargetScanner(opts)

    with console.status(f"Scanning [bold cyan]{url}[/]…"):
        report = scanner.scan(url)

    # ── Summary header ────────────────────────────────────────────────────────
    hdr = Table(show_header=False, border_style="bold magenta")
    hdr.add_column("Field",  style="bold cyan")
    hdr.add_column("Value")
    hdr.add_row("Target",          report.target)
    hdr.add_row("Scan time (UTC)", report.scan_time_utc)
    hdr.add_row("Duration",        f"{report.duration_seconds}s")
    hdr.add_row("Pages crawled",   str(report.pages_crawled))
    console.print(hdr)

    # ── Server info ───────────────────────────────────────────────────────────
    if report.server_info:
        t = Table(title="Server / Response Headers", border_style="cyan", show_header=True)
        t.add_column("Header", style="bold cyan")
        t.add_column("Value")
        for k, v in report.server_info.items():
            t.add_row(k, v[:100])
        console.print(t)

    # ── Technology summary ────────────────────────────────────────────────────
    if report.tech_summary:
        t = Table(title="Detected Technologies (by evidence weight)", border_style="bold magenta")
        t.add_column("Technology",  style="bold")
        t.add_column("Evidence Weight", justify="right")
        t.add_column("Category")

        # Build category lookup from first evidence per tech
        cat_lookup: dict[str, str] = {}
        for ev in report.tech_evidence:
            if ev.tech not in cat_lookup:
                cat_lookup[ev.tech] = ev.category

        for tech, weight in report.tech_summary.items():
            cat = cat_lookup.get(tech, "")
            colour = {
                "exposure": "red", "runtime": "yellow",
                "framework": "cyan", "webserver": "green",
                "cms": "magenta", "api": "blue",
                "frontend": "white", "upload": "bright_yellow",
                "security_header_present": "dim",
            }.get(cat, "white")
            t.add_row(f"[{colour}]{tech}[/]", str(weight), cat)
        console.print(t)
    else:
        console.print("[dim]No technology signatures matched.[/]")

    # ── Upload endpoints ──────────────────────────────────────────────────────
    if report.upload_endpoints:
        t = Table(title="Upload Endpoints Discovered", border_style="bright_yellow")
        t.add_column("URL",          style="bold")
        t.add_column("Method")
        t.add_column("Enctype")
        t.add_column("Accept")
        t.add_column("Source page")
        for ep in report.upload_endpoints:
            t.add_row(
                ep.url[:60], ep.method, ep.enctype[:30],
                ", ".join(ep.accept)[:40] or "—",
                ep.source_page[:50],
            )
        console.print(t)
    else:
        console.print("[dim]No upload endpoints found in crawled HTML.[/]")

    # ── Security gaps ─────────────────────────────────────────────────────────
    if report.security_gaps:
        t = Table(title="Security Header Gaps", border_style="red")
        t.add_column("Header",   style="bold cyan")
        t.add_column("Severity", justify="center")
        t.add_column("Impact")
        sev_colours = {"high": "red", "medium": "yellow", "low": "dim"}
        for g in report.security_gaps:
            col = sev_colours.get(g.severity, "white")
            t.add_row(g.header, f"[{col}]{g.severity.upper()}[/]", g.gap[:80])
        console.print(t)
    else:
        console.print("[bold green]✓ All checked security headers are present.[/]")

    # ── Exposed paths ─────────────────────────────────────────────────────────
    if report.exposed_paths:
        t = Table(title="High-Interest Exposed Paths", border_style="red")
        t.add_column("Path + Status")
        for ep in report.exposed_paths:
            t.add_row(f"[red]{ep}[/]")
        console.print(t)

    # ── Polyglot recommendations ──────────────────────────────────────────────
    if report.recommendations:
        t = Table(title="Polyglot Attack Recommendations", border_style="bold magenta")
        t.add_column("Trigger Evidence", style="bold cyan")
        t.add_column("Strategy")
        t.add_column("Host Formats")
        t.add_column("Risk")
        t.add_column("Note")
        for rec in report.recommendations:
            risk_colour = "red" if "RCE" in rec.risk else "yellow"
            t.add_row(
                rec.trigger[:45],
                f"[bold]{rec.strategy.upper()}[/]",
                ", ".join(rec.host_formats),
                f"[{risk_colour}]{rec.risk}[/]",
                rec.payload_note[:60],
            )
        console.print(t)

        console.print(
            "\n[bold yellow]⚡ To build a recommended polyglot:[/]\n"
            "  [dim]python -m PolyMorph build <host_file> <payload_file> "
            "-A <host_fmt> -B <payload_fmt> -s <strategy> -o output.ext[/]"
        )
    else:
        console.print("[dim]No polyglot recommendations generated.[/]")

    # ── Save JSON ─────────────────────────────────────────────────────────────
    if out:
        report.save(out)
        console.print(f"\n[bold green]✓ Full JSON report saved to:[/] {out}")
    else:
        console.print(
            "\n[dim]Tip: use --out report.json to save the full report.[/]"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
