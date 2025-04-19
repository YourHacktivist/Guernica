import difflib
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import re
import matplotlib.pyplot as plt
import os
import sys


def is_iptables_file(content: List[str]) -> bool:
    """
    Checks if the file content resembles an iptables configuration.
    Args: content: List of file lines
    Returns: 
        bool: True if the file appears to be an iptables configuration
    """
    # Characteristic patterns of iptables files
    iptables_patterns = [
        r'iptables',
        r'-A\s+\w+',
        r'-p\s+\w+',
        r'--dport',
        r'--sport',
        r'-j\s+\w+',
        r'ACCEPT|DROP|REJECT'
    ]
    
    if not content:
        return False
    
    # Check if at least a certain number of lines match iptables patterns
    matches = 0
    threshold = 3  # Minimum number of matches to consider it an iptables file
    
    for line in content:
        for pattern in iptables_patterns:
            if re.search(pattern, line):
                matches += 1
                break
        
        if matches >= threshold:
            return True
    
    return False


def read_file(path: str) -> List[str]:
    """
    Reads a file and returns its content as a list of lines.
    Args:
        path: Path to the file
    Returns: List of file lines
    Raises:
        FileNotFoundError: If the file doesn't exist
    """
    if not Path(path).is_file():
        raise FileNotFoundError(f"File not found: {path}")
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        return lines
    except UnicodeDecodeError:
        try:
            with open(path, 'r', encoding='latin-1') as f:
                return f.readlines()
        except Exception as e:
            raise IOError(f"Unable to read file {path}: {str(e)}")


def normalize_iptables_config(lines: List[str]) -> List[str]:
    """
    Normalizes an iptables configuration to facilitate comparison.
    
    - Removes comment lines
    - Removes empty lines
    - Normalizes spaces
    - Fixes incorrect double dashes (--A should be -A)
    - Sorts rules by chain
    
    Args:
        lines: List of configuration lines
    Returns: List of normalized lines
    """
    normalized = []
    for line in lines:
        # Ignore comments and empty lines
        if line.strip() and not line.strip().startswith('#'):
            # Fix common errors with double dashes for commands
            fixed_line = re.sub(r'--([A-Z])', r'-\1', line.strip())
            # Normalize spaces
            normalized_line = re.sub(r'\s+', ' ', fixed_line)
            normalized.append(normalized_line)
    
    # Sort rules (optional, can be disabled if order is important)
    return sorted(normalized)


def compare_configs(before: List[str], after: List[str]) -> List[str]:
    """
    Compares two configurations and generates a diff.
    
    Args:
        before: Configuration before
        after: Configuration after
    
    Returns:
        List of differences in unified diff format
    """
    diff = list(difflib.unified_diff(before, after, lineterm=''))
    return [line for line in diff if not line.startswith('---') and not line.startswith('+++')]


def detect_security_risks(diff_lines: List[str]) -> List[str]:
    """
    Detects security risks in the changes.
    
    Args:
        diff_lines: Diff lines
    
    Returns:
        List of detected security risks
    """
    critical_ports = {
        22: "SSH - Used for remote access, often targeted by attackers.",
        80: "HTTP - Often unencrypted, vulnerable to various attacks.",
        443: "HTTPS - Critical for secure web traffic, targeted for MiTM attacks.",
        8080: "HTTP Proxy - Can bypass normal firewall rules, potentially dangerous.",
        53: "DNS - Can be used for DNS amplification attacks.",
        3306: "MySQL - Often targeted in brute force attacks.",
        21: "FTP - Unencrypted file transfers, vulnerable to interception.",
        23: "Telnet - Unencrypted communication, easily intercepted.",
        1433: "MS SQL Server - Database often targeted.",
        3389: "RDP - Remote desktop access, vulnerable to brute force attacks.",
        5432: "PostgreSQL - Target database for attacks.",
        27017: "MongoDB - NoSQL database, often misconfigured."
    }
    
    # Risky rule patterns
    risky_patterns = [
        (r'iptables.*-j\s+ACCEPT\s*$', "High risk: Unconditional acceptance rule without restrictions"),
        (r'iptables.*-A\s+INPUT.*-j\s+ACCEPT\s*$', "Medium risk: Input acceptance rule without specific filters"),
        (r'iptables.*-A\s+FORWARD.*-j\s+ACCEPT\s*$', "High risk: Forwarding rule without restrictions, potential pivot point"),
        
        (r'iptables.*--dport\s+0:65535', "Critical risk: Complete port range open"),
        (r'iptables.*--dport\s+1:1024', "High risk: All privileged ports open"),
        (r'iptables.*--dport\s+[0-9]+:[0-9]+', "Medium risk: Port range detected, verify if necessary"),
        
        (r'iptables.*-s\s+0\.0\.0\.0/0.*-j\s+ACCEPT', "High risk: Accepting traffic from any source IP"),
        (r'iptables.*-A\s+INPUT\s+-s\s+192\.168\.[0-9]+\.[0-9]+/[0-9]+.*-j\s+ACCEPT', "Low risk: Private network access rule, verify scope"),
        
        (r'iptables.*-j\s+DROP.*--state\s+INVALID', "Medium risk: Security rule for invalid packets modified/removed"),
        (r'iptables.*-j\s+DROP.*--state\s+NEW.*-m\s+state\s+--state\s+ESTABLISHED', "High risk: State tracking rule modified/removed"),
        
        (r'iptables.*:INPUT\s+ACCEPT', "High risk: Default INPUT policy set to ACCEPT"),
        (r'iptables.*:FORWARD\s+ACCEPT', "High risk: Default FORWARD policy set to ACCEPT"),
        
        (r'iptables.*-A\s+INPUT.*--dport\s+3389.*-j\s+ACCEPT', "Medium risk: RDP port opened, vulnerable to brute force"),
        (r'iptables.*-A\s+INPUT.*--dport\s+22.*-j\s+ACCEPT\s*$', "Medium risk: SSH port opened without IP restriction"),
        (r'iptables.*-A\s+INPUT.*--dport\s+(1433|3306|5432|27017).*-j\s+ACCEPT\s*$', "High risk: Database port exposed without restrictions")
    ]

    risky_changes = []
    
    # Detection based on critical ports
    for line in diff_lines:
        if line.startswith('+'):
            # Port check
            port_match = re.search(r'--dport\s+(\d+)(?:-(\d+))?', line)
            if port_match:
                if port_match.group(2):  # Port range detected
                    start_port = int(port_match.group(1))
                    end_port = int(port_match.group(2))
                    for port in range(start_port, end_port + 1):
                        if port in critical_ports:
                            risky_changes.append(f"[bold red]Security Risk Detected![/bold red] - {line.strip()} (Port {port}: {critical_ports[port]})")
                else:  # Single port
                    port = int(port_match.group(1))
                    if port in critical_ports:
                        risky_changes.append(f"[bold red]Security Risk Detected![/bold red] - {line.strip()} ({critical_ports[port]})")
            
            # Pattern-based risk detection
            for pattern, description in risky_patterns:
                if re.search(pattern, line):
                    risky_changes.append(f"[bold yellow]Potential Risk![/bold yellow] - {line.strip()} ({description})")
    
    return risky_changes


def group_rules(diff_lines: List[str]) -> List[str]:
    """
    Groups similar additions by port.
    Args:
        diff_lines: Diff lines
    Returns: List of grouped rules
    """
    # Group similar additions by port
    grouped = {}
    for line in diff_lines:
        if line.startswith('+'):
            port_match = re.search(r'--dport\s+(\d+)(?:-(\d+))?', line)
            if port_match:
                port_key = port_match.group(0)  # Use the entire port match as key
                if port_key not in grouped:
                    grouped[port_key] = []
                grouped[port_key].append(line.strip())
    
    # Group by chain type
    chain_grouped = {}
    for line in diff_lines:
        if line.startswith('+'):
            chain_match = re.search(r'-A\s+(\w+)', line)
            if chain_match:
                chain = chain_match.group(1)
                if chain not in chain_grouped:
                    chain_grouped[chain] = []
                chain_grouped[chain].append(line.strip())
    
    # Combine the results
    grouped_lines = []
    
    # First by port
    if grouped:
        grouped_lines.append("[bold blue]--- Rules Grouped by Port ---[/bold blue]")
        for port_key, rules in grouped.items():
            grouped_lines.append(f"[bold green]{port_key} Rules[/bold green]:")
            for rule in rules:
                grouped_lines.append(f"    {rule}")
    
    # Then by chain
    if chain_grouped:
        grouped_lines.append("\n[bold blue]--- Rules Grouped by Chain ---[/bold blue]")
        for chain, rules in chain_grouped.items():
            grouped_lines.append(f"[bold green]Chain {chain} Rules[/bold green]:")
            for rule in rules:
                grouped_lines.append(f"    {rule}")
    
    return grouped_lines


def calculate_impact_metrics(diff_lines: List[str]) -> Dict[str, float]:
    """
    Calculates various metrics to assess the impact of changes.
    Args:
        diff_lines: Diff lines
    Returns: Dictionary containing the metrics
    """
    add_count = sum(1 for line in diff_lines if line.startswith('+'))
    remove_count = sum(1 for line in diff_lines if line.startswith('-'))
    
    # Weights for different types of changes
    weight_add = 1.5
    weight_remove = 1.0
    
    # Chaos index (weighted sum of changes)
    chaos_score = add_count * weight_add + remove_count * weight_remove
    
    max_expected_score = 50  # Base value
    total_lines = len([line for line in diff_lines if line.startswith('+') or line.startswith('-') or line.startswith(' ')])
    if total_lines > 0:
        max_expected_score = max(50, min(200, total_lines / 2))
    
    # Scaling to a 0-100 range
    scaled_chaos = min(100, (chaos_score / max_expected_score) * 100)
    
    # Calculate additional metrics
    input_rule_changes = sum(1 for line in diff_lines if (line.startswith('+') or line.startswith('-')) and 'INPUT' in line)
    output_rule_changes = sum(1 for line in diff_lines if (line.startswith('+') or line.startswith('-')) and 'OUTPUT' in line)
    forward_rule_changes = sum(1 for line in diff_lines if (line.startswith('+') or line.startswith('-')) and 'FORWARD' in line)
    
    return {
        'chaos_score': round(scaled_chaos, 2),
        'additions': add_count,
        'removals': remove_count,
        'input_changes': input_rule_changes,
        'output_changes': output_rule_changes,
        'forward_changes': forward_rule_changes
    }


def generate_report(diff_lines: List[str], metrics: Dict[str, float], risky_changes: List[str], grouped_rules: List[str], export_path: Optional[str] = None, text_output: Optional[str] = None, no_visualization: bool = False):
    """
    Generates a comprehensive report of the changes.
    
    Args:
        diff_lines: Diff lines
        metrics: Impact metrics
        risky_changes: Detected security risks
        grouped_rules: Grouped rules
        export_path: Optional path to export the HTML report
        text_output: Optional path to export the text report
        no_visualization: Whether to skip visualization
    """
    console = Console(record=True if export_path or text_output else False)

    # Header
    console.print(Panel("[bold]Guernica - Attack Surface Deformation Analysis[/bold]", style="bold magenta", expand=False))

    # Summary
    console.print("\n")
    console.print(Panel("[bold]Change Summary[/bold]", style="bold cyan", expand=False))
    summary_table = Table(show_header=True, header_style="bold cyan")
    summary_table.add_column("Metric")
    summary_table.add_column("Value")
    
    summary_table.add_row("Total Changes", str(metrics['additions'] + metrics['removals']))
    summary_table.add_row("Additions", str(metrics['additions']))
    summary_table.add_row("Removals", str(metrics['removals']))
    summary_table.add_row("INPUT Chain Changes", str(metrics['input_changes']))
    summary_table.add_row("OUTPUT Chain Changes", str(metrics['output_changes']))
    summary_table.add_row("FORWARD Chain Changes", str(metrics['forward_changes']))
    summary_table.add_row("Chaos Index", f"{metrics['chaos_score']}/100")
    
    console.print(summary_table)

    # Differences Detected
    console.print("\n")
    console.print(Panel("[bold]Differences Detected[/bold]", style="bold green", expand=False))

    # Create table for differences
    table = Table(show_header=True, header_style="bold magenta", show_lines=True)
    table.add_column("Line", style="dim", width=6)
    table.add_column("Diff")

    # Parse diff and apply color
    for i, line in enumerate(diff_lines, 1):
        if line.startswith('@@'):
            # For diff range, make it more readable
            table.add_row(f"{i}", Text(line.strip(), style="bold cyan"))
        elif line.startswith('+'):
            # Additions in green
            table.add_row(f"{i}", Text(line.strip(), style="bold green"))
        elif line.startswith('-'):
            # Deletions in red
            table.add_row(f"{i}", Text(line.strip(), style="bold red"))
        else:
            # Normal lines (unchanged) in white
            table.add_row(f"{i}", line.strip())

    console.print(table)

    # Security Risks
    console.print("\n")
    if risky_changes:
        console.print(Panel("[bold]Security Risks Detected[/bold]", style="bold red", expand=False))
        for risk in risky_changes:
            console.print(risk)
    else:
        console.print(Panel("[bold]No Security Risks Detected[/bold]", style="bold green", expand=False))

    # Grouped Rules
    if grouped_rules:
        console.print("\n")
        console.print(Panel("[bold]Rule Analysis[/bold]", style="bold blue", expand=False))
        for group in grouped_rules:
            console.print(group)

    # Chaos Index
    console.print("\n")
    console.print(Panel("[bold]Chaos Index[/bold]", style="bold red", expand=False))
    console.print(f"[bold yellow]Chaos Index: {metrics['chaos_score']}/100[/bold yellow]")
    
    # Description of the chaos index
    chaos_description = "Low impact, minimal changes" if metrics['chaos_score'] < 25 else \
                        "Moderate impact, significant changes" if metrics['chaos_score'] < 50 else \
                        "High impact, major reconfiguration" if metrics['chaos_score'] < 75 else \
                        "Extreme impact, complete overhaul"
    console.print(f"[bold]Assessment: [/bold]{chaos_description}")

    # Export to HTML if requested
    if export_path:
        html = console.export_html()
        with open(export_path, "w") as f:
            f.write(html)
        console.print(f"\n[bold green]Report exported to {export_path}[/bold green]")

    # Export to text if requested
    if text_output:
        text = console.export_text()
        with open(text_output, "w") as f:
            f.write(text)
        console.print(f"\n[bold green]Text report exported to {text_output}[/bold green]")

    # Generate visualization only if not disabled
    if not no_visualization:
        visualize_changes(metrics)


def visualize_changes(metrics: Dict[str, float]):
    """
    Visualizes the changes and metrics.
    
    Args:
        metrics: Impact metrics
    """
    # Create a figure with adjusted size to avoid tight_layout warnings
    plt.figure(figsize=(14, 10))
    
    # Add padding to avoid tight layout issues
    plt.subplots_adjust(hspace=0.4, wspace=0.3, top=0.95, bottom=0.08, left=0.1, right=0.95)
    
    # First subplot: Additions vs Removals
    plt.subplot(2, 2, 1)
    bars = plt.bar(["Additions", "Removals"], [metrics['additions'], metrics['removals']], 
                  color=['#4CAF50', '#D32F2F'], width=0.5)
    plt.title("Rule Changes", fontsize=14)
    plt.ylabel("Number of Changes", fontsize=12)
    
    # Add labels on the bars
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, yval + 0.1, str(int(yval)), 
                ha='center', va='bottom', fontsize=10)
    
    # Second subplot: Chain Changes
    plt.subplot(2, 2, 2)
    chain_bars = plt.bar(["INPUT", "OUTPUT", "FORWARD"], 
                        [metrics['input_changes'], metrics['output_changes'], metrics['forward_changes']], 
                        color=['#2196F3', '#FF9800', '#9C27B0'], width=0.5)
    plt.title("Changes by Chain", fontsize=14)
    plt.ylabel("Number of Changes", fontsize=12)
    
    # Add labels on the bars
    for bar in chain_bars:
        yval = bar.get_height()
        if yval > 0:  # Only add labels if there's a value
            plt.text(bar.get_x() + bar.get_width() / 2, yval + 0.1, str(int(yval)), 
                    ha='center', va='bottom', fontsize=10)
    
    # Third subplot: Chaos Index Gauge - using the bottom row
    ax = plt.subplot(2, 1, 2)
    chaos = metrics['chaos_score']
    plt.barh(["Chaos Index"], [chaos], color=get_color_for_chaos(chaos), height=0.3)
    plt.xlim(0, 100)
    plt.title("Chaos Index (Impact Assessment)", fontsize=14)
    
    # Add threshold markers
    for threshold in [25, 50, 75]:
        plt.axvline(x=threshold, color='gray', linestyle='--', alpha=0.7)
    
    # Add labels for the thresholds - adjusted y position to avoid layout issues
    y_pos = 0.8  # Adjusted y position for labels
    plt.text(12.5, y_pos, "Low", ha='center', fontsize=10)
    plt.text(37.5, y_pos, "Moderate", ha='center', fontsize=10)
    plt.text(62.5, y_pos, "High", ha='center', fontsize=10)
    plt.text(87.5, y_pos, "Extreme", ha='center', fontsize=10)
    
    # Add the actual value - ensure it doesn't go off the chart
    val_x_pos = min(chaos + 2, 95)
    plt.text(val_x_pos, 0, f"{chaos}/100", va='center', fontsize=12, fontweight='bold')
    
    # Set y-axis limit to provide more space for labels
    plt.ylim(-0.5, 1.5)
    
    # Remove tight_layout() call that was causing the warning
    # Instead use the subplots_adjust settings from above
    plt.show()


def get_color_for_chaos(chaos_score: float) -> str:
    """
    Returns a color based on the chaos score.
    Args:
        chaos_score: The chaos score
    
    Returns: Color code
    """
    if chaos_score < 25:
        return '#4CAF50'  # Green
    elif chaos_score < 50:
        return '#FFC107'  # Amber
    elif chaos_score < 75:
        return '#FF9800'  # Orange
    else:
        return '#F44336'  # Red


def main():
    """Main function to run the program."""
    import argparse

    parser = argparse.ArgumentParser(description="Guernica - Compare iptables configurations and compute chaos index.")
    parser.add_argument("--before", "-b", required=True, help="Path to baseline iptables configuration")
    parser.add_argument("--after", "-a", required=True, help="Path to changed iptables configuration")
    parser.add_argument("--export", "-e", help="Export report to HTML file")
    parser.add_argument("--output", "-o", help="Export report to plain text file")
    parser.add_argument("--no-normalize", action="store_true", help="Skip normalization of configurations")
    parser.add_argument("--no-visualization", action="store_true", help="Skip visualization")
    
    args = parser.parse_args()
    
    try:
        # Check file extensions
        valid_extensions = ['.txt', '.rules', '.iptables']
        validation_errors = []
        
        before_file = Path(args.before)
        after_file = Path(args.after)
        
        if before_file.suffix.lower() not in valid_extensions:
            validation_errors.append(f"The file {args.before} does not have a valid extension. Valid extensions are: {', '.join(valid_extensions)}")
        
        if after_file.suffix.lower() not in valid_extensions:
            validation_errors.append(f"The file {args.after} does not have a valid extension. Valid extensions are: {', '.join(valid_extensions)}")
        
        # If there are extension errors, display them and exit
        if validation_errors:
            console = Console()
            for error in validation_errors:
                console.print(Panel(f"[bold red]Error:[/bold red] {error}", style="red", expand=False))
            return 1
        
        # Read configurations
        console = Console()
        console.print(Panel("[bold]Reading configurations...[/bold]", style="dim blue", expand=False))
        before_lines = read_file(args.before)
        after_lines = read_file(args.after)
        
        # Validate that files are iptables configurations
        validation_errors = []
        
        if not is_iptables_file(before_lines):
            validation_errors.append(f"The file {args.before} does not appear to be an iptables configuration.")
        
        if not is_iptables_file(after_lines):
            validation_errors.append(f"The file {args.after} does not appear to be an iptables configuration.")
        
        # Si un des fichiers ou les deux ne sont pas valides, afficher les erreurs et quitter
        if validation_errors:
            for error in validation_errors:
                console.print(Panel(f"[bold red]Error:[/bold red] {error}", style="red", expand=False))
            return 1
        
        # Normalize configurations if requested
        if not args.no_normalize:
            before_lines = normalize_iptables_config(before_lines)
            after_lines = normalize_iptables_config(after_lines)
        
        # Compare configurations
        console.print(Panel("[bold]Comparing configurations...[/bold]", style="dim blue", expand=False))
        diff = compare_configs(before_lines, after_lines)
        
        if not diff:
            console.print(Panel("[bold yellow]No differences detected between the configurations.[/bold yellow]", 
                               style="yellow", expand=False))
            return 0
        
        # Analyze changes
        console.print(Panel("[bold]Analyzing changes...[/bold]", style="dim blue", expand=False))
        risky_changes = detect_security_risks(diff)
        grouped_rules = group_rules(diff)
        metrics = calculate_impact_metrics(diff)
        
        # Generate report
        generate_report(diff, metrics, risky_changes, grouped_rules, 
                       args.export, args.output, args.no_visualization)
        
        return 0
        
    except FileNotFoundError as e:
        console = Console()
        console.print(Panel(f"[bold red]Error:[/bold red] {str(e)}", style="red", expand=False))
        return 1
    except Exception as e:
        console = Console()
        console.print(Panel(f"[bold red]Error:[/bold red] An unexpected error occurred: {str(e)}", 
                           style="red", expand=False))
        return 1

if __name__ == "__main__":
    sys.exit(main())