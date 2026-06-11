"""Rich terminal output for audit results."""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich import box

from ..engine import AuditResult
from ..rules.base import Severity

console = Console()

_SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
    "SAFE": "bold green",
    "PASS": "green",
    "FAIL": "red",
}

_IMPACT_COLOR = {
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}


def _sev(s: str) -> str:
    c = _SEV_COLOR.get(s, "white")
    return f"[{c}]{s}[/{c}]"


def print_header(result: AuditResult):
    counts = result.severity_counts()
    risk = result.risk_level()
    rc = result.risk_color()
    n_lines = len(result.parsed.lines)
    n_contracts = len(result.parsed.contracts)
    pragma = result.parsed.pragma or "unknown"

    console.print()
    console.print(Panel(
        f"  [bold]File:[/bold]      {result.source_file}\n"
        f"  [bold]Pragma:[/bold]    {pragma}\n"
        f"  [bold]Contracts:[/bold] {n_contracts}\n"
        f"  [bold]Lines:[/bold]     {n_lines}\n\n"
        f"  [bold]Risk Level:[/bold]  [{rc}]{'[*] ' * 5 if risk == 'CRITICAL' else '[*] ' * 4 if risk == 'HIGH' else '[*] ' * 3 if risk == 'MEDIUM' else '[*] ' * 2 if risk == 'LOW' else '[*] '}[/{rc}] [{rc}]{risk}[/{rc}]\n\n"
        f"  [bold red]CRITICAL[/bold red] {counts['CRITICAL']}  "
        f"[red]HIGH[/red] {counts['HIGH']}  "
        f"[yellow]MEDIUM[/yellow] {counts['MEDIUM']}  "
        f"[cyan]LOW[/cyan] {counts['LOW']}  "
        f"[dim]INFO[/dim] {counts['INFO']}",
        title="[bold][ Mantle Smart Contract Audit Assistant ][/bold]",
        subtitle=f"[dim]{result.source_file}[/dim]",
        border_style="bright_blue",
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    ))


def print_security_section(result: AuditResult):
    console.print()
    console.rule("[bold red]SECURITY ANALYSIS[/bold red]")

    findings = result.security_findings
    if not findings:
        console.print("\n  [bold green][OK] No security vulnerabilities detected.[/bold green]\n")
        return

    # Summary table
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE_HEAVY,
                  padding=(0, 1), show_edge=True)
    table.add_column("ID", style="dim bold", width=6, no_wrap=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Title", width=45)
    table.add_column("Line(s)", width=8, justify="right")
    table.add_column("L2", width=4, justify="center")

    for f in findings:
        l2_badge = "[bold magenta]L2[/bold magenta]" if f.l2_specific else ""
        table.add_row(
            f.rule_id,
            _sev(f.severity.name),
            f.title,
            f.line_str(),
            l2_badge,
        )
    console.print(table)

    # Details for CRITICAL and HIGH
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            color = _SEV_COLOR.get(f.severity.name, "white")
            l2_tag = " [magenta][Mantle L2][/magenta]" if f.l2_specific else ""
            content = (
                f"[bold]Line(s):[/bold] {f.line_str()}\n\n"
                f"[bold]Description:[/bold]\n{f.description}\n\n"
                f"[bold]Recommendation:[/bold]\n{f.recommendation}"
            )
            if f.code_snippet:
                content += f"\n\n[bold]Code:[/bold]\n[dim]{f.code_snippet[:200]}[/dim]"
            console.print(Panel(
                content,
                title=f"[{color}][{f.rule_id}] {f.title}[/{color}]{l2_tag}",
                border_style=color.split()[-1],
                padding=(0, 2),
            ))


def print_gas_section(result: AuditResult):
    console.print()
    console.rule("[bold yellow]GAS OPTIMIZATION — MANTLE L2[/bold yellow]")

    findings = result.gas_findings
    if not findings:
        console.print("\n  [bold green][OK] No gas optimizations found.[/bold green]\n")
        return

    table = Table(show_header=True, header_style="bold", box=box.SIMPLE_HEAVY,
                  padding=(0, 1), show_edge=True)
    table.add_column("ID", style="dim bold", width=6)
    table.add_column("Impact", width=8)
    table.add_column("Title", width=50)
    table.add_column("Line(s)", width=8, justify="right")
    table.add_column("Mantle", width=7, justify="center")

    for f in findings:
        mantle = "[magenta]M[/magenta]" if f.mantle_specific else ""
        color = _IMPACT_COLOR.get(f.severity.name, "white")
        table.add_row(
            f.rule_id,
            f"[{color}]{f.severity.name}[/{color}]",
            f.title,
            f.line_str(),
            mantle,
        )
    console.print(table)

    for f in findings:
        if f.severity in (Severity.HIGH, Severity.MEDIUM):
            color = _IMPACT_COLOR.get(f.severity.name, "white")
            mantle_tag = " [magenta][Mantle L2][/magenta]" if f.mantle_specific else ""
            content = (
                f"[bold]Line(s):[/bold] {f.line_str()}\n\n"
                f"[bold]Description:[/bold]\n{f.description}\n\n"
                f"[bold]Recommendation:[/bold]\n{f.recommendation}"
            )
            console.print(Panel(
                content,
                title=f"[{color}][{f.rule_id}] {f.title}[/{color}]{mantle_tag}",
                border_style=color.split()[-1],
                padding=(0, 2),
            ))


def print_erc8004_section(result: AuditResult):
    console.print()
    console.rule("[bold blue]ERC-8004 AGENT IDENTITY COMPLIANCE[/bold blue]")

    score = result.compliance_score()
    score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    findings = result.compliance_findings
    is_compliant = score >= 80 and not any(
        f.severity == Severity.CRITICAL for f in findings
    )
    status = "[bold green]COMPLIANT[/bold green]" if is_compliant else "[bold red]NON-COMPLIANT[/bold red]"

    console.print(Panel(
        f"  [bold]Status:[/bold]            {status}\n"
        f"  [bold]Compliance Score:[/bold]  [{score_color}]{score}/100[/{score_color}]\n"
        f"  [bold]Issues Found:[/bold]      {len(findings)}",
        border_style="blue",
        padding=(0, 2),
    ))

    if findings:
        table = Table(show_header=True, header_style="bold", box=box.SIMPLE_HEAVY,
                      padding=(0, 1), show_edge=True)
        table.add_column("ID", style="dim bold", width=6)
        table.add_column("Severity", width=10)
        table.add_column("Requirement", width=55)
        table.add_column("Line", width=6, justify="right")

        for f in findings:
            table.add_row(
                f.rule_id,
                _sev(f.severity.name),
                f.title.replace("ERC-8004: ", ""),
                f.line_str(),
            )
        console.print(table)

        for f in findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                color = _SEV_COLOR.get(f.severity.name, "white")
                content = (
                    f"[bold]Description:[/bold]\n{f.description}\n\n"
                    f"[bold]Recommendation:[/bold]\n{f.recommendation}"
                )
                console.print(Panel(
                    content,
                    title=f"[{color}][{f.rule_id}] {f.title}[/{color}]",
                    border_style=color.split()[-1],
                    padding=(0, 2),
                ))


def print_summary(result: AuditResult):
    console.print()
    console.rule("[bold green]AUDIT COMPLETE[/bold green]")

    risk = result.risk_level()
    score = result.compliance_score()
    score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    counts = result.severity_counts()
    rc = result.risk_color()

    console.print(Panel(
        f"  [bold]Security Risk:[/bold]       [{rc}]{risk}[/{rc}]  "
        f"({counts['CRITICAL']}C / {counts['HIGH']}H / {counts['MEDIUM']}M / {counts['LOW']}L)\n"
        f"  [bold]Gas Optimizations:[/bold]   {len(result.gas_findings)} found "
        f"({sum(1 for f in result.gas_findings if f.severity.value >= 3)} high/medium impact)\n"
        f"  [bold]ERC-8004 Score:[/bold]      [{score_color}]{score}/100[/{score_color}]  "
        f"({len(result.compliance_findings)} issues)\n\n"
        f"  [dim]Powered by Mantle Audit Assistant — Track 5 AI DevTools[/dim]",
        title="[bold green]Summary[/bold green]",
        border_style="green",
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    ))


def print_full_report(result: AuditResult,
                      show_security=True, show_gas=True, show_erc8004=True):
    print_header(result)
    if show_security:
        print_security_section(result)
    if show_gas:
        print_gas_section(result)
    if show_erc8004:
        print_erc8004_section(result)
    print_summary(result)
