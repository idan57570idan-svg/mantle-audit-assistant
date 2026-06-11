#!/usr/bin/env python3
"""
Mantle Smart Contract Audit Assistant
Track 5: AI DevTools — Mantle Turing Test Hackathon 2026

Usage:
    python main.py audit <file.sol>
    python main.py audit <file.sol> --html report.html
    python main.py security <file.sol>
    python main.py gas <file.sol>
    python main.py erc8004 <file.sol>
    python main.py demo
"""
import sys
import os
import click
from rich.console import Console

from src.engine import AuditEngine
from src.report.terminal import print_full_report, print_security_section, print_gas_section, print_erc8004_section, print_header, print_summary
from src.report.html_report import generate_html

console = Console()


def _load(path: str) -> str:
    if not os.path.exists(path):
        console.print(f"[bold red]Error:[/bold red] File not found: {path}")
        sys.exit(1)
    if not path.endswith('.sol'):
        console.print(f"[yellow]Warning:[/yellow] {path} does not end with .sol")
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


@click.group()
@click.version_option("1.0.0", prog_name="mantle-audit")
def cli():
    """Mantle Smart Contract Audit Assistant

    Fully local static analysis for Solidity contracts targeting Mantle L2.
    No API key required -- everything runs on your machine.

    Checks: 25 security vulnerabilities | 15 gas optimizations | 15 ERC-8004 compliance rules
    """
    pass


@cli.command()
@click.argument("contract", type=click.Path())
@click.option("--html", "html_out", default=None, metavar="FILE",
              help="Also generate an HTML report (e.g. --html report.html)")
@click.option("--json", "json_out", default=None, metavar="FILE",
              help="Also save findings as JSON")
@click.option("--no-gas", is_flag=True, help="Skip gas optimization analysis")
@click.option("--no-erc8004", is_flag=True, help="Skip ERC-8004 compliance check")
def audit(contract, html_out, json_out, no_gas, no_erc8004):
    """Run full audit: security + gas + ERC-8004 compliance."""
    source = _load(contract)
    engine = AuditEngine(
        run_security=True,
        run_gas=not no_gas,
        run_erc8004=not no_erc8004
    )
    result = engine.analyze(source, label=os.path.basename(contract))
    print_full_report(result)

    if html_out:
        generate_html(result, html_out)
        console.print(f"\n[bold green][OK] HTML report saved:[/bold green] {html_out}")

    if json_out:
        import json
        data = {
            "file": contract,
            "risk_level": result.risk_level(),
            "compliance_score": result.compliance_score(),
            "security": [
                {"id": f.rule_id, "title": f.title, "severity": f.severity.name,
                 "lines": f.lines, "description": f.description,
                 "recommendation": f.recommendation, "l2_specific": f.l2_specific}
                for f in result.security_findings
            ],
            "gas": [
                {"id": f.rule_id, "title": f.title, "impact": f.severity.name,
                 "lines": f.lines, "description": f.description,
                 "mantle_specific": f.mantle_specific}
                for f in result.gas_findings
            ],
            "compliance": [
                {"id": f.rule_id, "title": f.title, "severity": f.severity.name,
                 "lines": f.lines, "description": f.description}
                for f in result.compliance_findings
            ],
        }
        with open(json_out, 'w', encoding='utf-8') as jf:
            json.dump(data, jf, indent=2)
        console.print(f"[bold green][OK] JSON report saved:[/bold green] {json_out}")


@cli.command()
@click.argument("contract", type=click.Path())
@click.option("--html", "html_out", default=None, metavar="FILE")
def security(contract, html_out):
    """Security vulnerability analysis only."""
    source = _load(contract)
    engine = AuditEngine(run_security=True, run_gas=False, run_erc8004=False)
    result = engine.analyze(source, label=os.path.basename(contract))
    print_header(result)
    print_security_section(result)
    print_summary(result)
    if html_out:
        generate_html(result, html_out)
        console.print(f"\n[bold green][OK] HTML report saved:[/bold green] {html_out}")


@cli.command()
@click.argument("contract", type=click.Path())
@click.option("--html", "html_out", default=None, metavar="FILE")
def gas(contract, html_out):
    """Gas optimization analysis for Mantle L2."""
    source = _load(contract)
    engine = AuditEngine(run_security=False, run_gas=True, run_erc8004=False)
    result = engine.analyze(source, label=os.path.basename(contract))
    print_header(result)
    print_gas_section(result)
    print_summary(result)
    if html_out:
        generate_html(result, html_out)
        console.print(f"\n[bold green][OK] HTML report saved:[/bold green] {html_out}")


@cli.command()
@click.argument("contract", type=click.Path())
@click.option("--html", "html_out", default=None, metavar="FILE")
def erc8004(contract, html_out):
    """ERC-8004 Agent Identity NFT compliance check."""
    source = _load(contract)
    engine = AuditEngine(run_security=False, run_gas=False, run_erc8004=True)
    result = engine.analyze(source, label=os.path.basename(contract))
    print_header(result)
    print_erc8004_section(result)
    print_summary(result)
    if html_out:
        generate_html(result, html_out)
        console.print(f"\n[bold green][OK] HTML report saved:[/bold green] {html_out}")


@cli.command()
def demo():
    """Run audit on all sample contracts and show results."""
    samples = [
        ("contracts/vulnerable/reentrancy_example.sol", "Security Demo"),
        ("contracts/vulnerable/gas_wasteful.sol", "Gas Optimization Demo"),
        ("contracts/vulnerable/erc8004_incomplete.sol", "ERC-8004 Compliance Demo"),
    ]
    engine = AuditEngine()
    for path, label in samples:
        if not os.path.exists(path):
            console.print(f"[yellow]Skipping {path} — not found[/yellow]")
            continue
        console.rule(f"[bold cyan]{label}[/bold cyan]")
        with open(path, 'r', encoding='utf-8') as f:
            source = f.read()
        result = engine.analyze(source, label=os.path.basename(path))
        print_full_report(result)


if __name__ == "__main__":
    cli()
