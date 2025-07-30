import typer
import subprocess
from pathlib import Path

app = typer.Typer(help="Unified CLI for Jira Tool - bulk create, update, comment, status, transition, attach, delete, sync.")
SCRIPTS_DIR = Path(__file__).parent / "scripts"


def run_script(script_name: str, args: list):
    script_path = SCRIPTS_DIR / script_name
    cmd = ["python", str(script_path)] + args
    typer.echo(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd)

@app.command()
def create(
    excel: str = typer.Argument(..., help="Excel file path"),
    url: str = typer.Argument(..., help="Jira URL"),
    token: str = typer.Argument(..., help="Jira token"),
    project: str = typer.Argument(..., help="Project key"),
    sheet: str = typer.Option("0", help="Sheet name or index"),
    summary_col: str = typer.Option("summary", help="Summary column"),
    desc_col: str = typer.Option("description", help="Description column"),
    id_col: str = typer.Option("ticket_id", help="ID column"),
    db: str = typer.Option("tickets.db", help="SQLite DB path"),
    table: str = typer.Option("tickets", help="Table name"),
    debug: bool = typer.Option(False, help="Enable debug")
):
    """Bulk create Jira tickets."""
    args = [
        "--excel", excel,
        "--url", url,
        "--token", token,
        "--project", project,
        "--sheet", sheet,
        "--summary_col", summary_col,
        "--desc_col", desc_col,
        "--id_col", id_col,
        "--db", db,
        "--table", table
    ]
    if debug:
        args.append("--debug")
    run_script("bulk_create_sync.py", args)

@app.command()
def update(
    excel: str = typer.Argument(..., help="Excel file path"),
    url: str = typer.Argument(..., help="Jira URL"),
    token: str = typer.Argument(..., help="Jira token"),
    fields: str = typer.Argument(..., help="Fields to update (space-separated)"),
    sheet: str = typer.Option("0", help="Sheet name or index"),
    id_col: str = typer.Option("ticket_id", help="ID column"),
    db: str = typer.Option("tickets.db", help="SQLite DB path"),
    table: str = typer.Option("tickets", help="Table name"),
    debug: bool = typer.Option(False, help="Enable debug")
):
    """Bulk update Jira tickets."""
    args = [
        "--excel", excel,
        "--url", url,
        "--token", token,
        "--sheet", sheet,
        "--id_col", id_col,
        "--db", db,
        "--table", table
    ] + fields.split()
    if debug:
        args.append("--debug")
    run_script("bulk_update_sync.py", args)

@app.command()
def comment(
    excel: str = typer.Argument(..., help="Excel file path"),
    url: str = typer.Argument(..., help="Jira URL"),
    token: str = typer.Argument(..., help="Jira token"),
    sheet: str = typer.Option("0", help="Sheet name or index"),
    id_col: str = typer.Option("ticket_id", help="ID column"),
    comment_col: str = typer.Option("comment", help="Comment column"),
    db: str = typer.Option("tickets.db", help="SQLite DB path"),
    table: str = typer.Option("tickets", help="Table name"),
    debug: bool = typer.Option(False, help="Enable debug")
):
    """Bulk add comments to Jira tickets."""
    args = [
        "--excel", excel,
        "--url", url,
        "--token", token,
        "--sheet", sheet,
        "--id_col", id_col,
        "--comment_col", comment_col,
        "--db", db,
        "--table", table
    ]
    if debug:
        args.append("--debug")
    run_script("bulk_comment_sync.py", args)

@app.command()
def status(
    excel: str = typer.Argument(..., help="Excel file path"),
    url: str = typer.Argument(..., help="Jira URL"),
    token: str = typer.Argument(..., help="Jira token"),
    sheet: str = typer.Option("0", help="Sheet name or index"),
    id_col: str = typer.Option("ticket_id", help="ID column"),
    status_col: str = typer.Option("status", help="Status column"),
    db: str = typer.Option("tickets.db", help="SQLite DB path"),
    table: str = typer.Option("tickets", help="Table name"),
    debug: bool = typer.Option(False, help="Enable debug")
):
    """Fetch Jira ticket status."""
    args = [
        "--excel", excel,
        "--url", url,
        "--token", token,
        "--sheet", sheet,
        "--id_col", id_col,
        "--status_col", status_col,
        "--db", db,
        "--table", table
    ]
    if debug:
        args.append("--debug")
    run_script("bulk_status_sync.py", args)

@app.command()
def transition(
    excel: str = typer.Argument(..., help="Excel file path"),
    url: str = typer.Argument(..., help="Jira URL"),
    token: str = typer.Argument(..., help="Jira token"),
    sheet: str = typer.Option("0", help="Sheet name or index"),
    id_col: str = typer.Option("ticket_id", help="ID column"),
    status_col: str = typer.Option("new_status", help="Status column"),
    db: str = typer.Option("tickets.db", help="SQLite DB path"),
    table: str = typer.Option("tickets", help="Table name"),
    debug: bool = typer.Option(False, help="Enable debug")
):
    """Change Jira ticket status."""
    args = [
        "--excel", excel,
        "--url", url,
        "--token", token,
        "--sheet", sheet,
        "--id_col", id_col,
        "--status_col", status_col,
        "--db", db,
        "--table", table
    ]
    if debug:
        args.append("--debug")
    run_script("bulk_transition_sync.py", args)

@app.command()
def attach(
    dir: str = typer.Argument(..., help="Directory with files"),
    excel: str = typer.Argument(..., help="Excel file path"),
    url: str = typer.Argument(..., help="Jira URL"),
    token: str = typer.Argument(..., help="Jira token"),
    sheet: str = typer.Option("0", help="Sheet name or index"),
    id_col: str = typer.Option("ticket_id", help="ID column"),
    evidence_col: str = typer.Option("Evidence", help="Evidence column"),
    pattern: str = typer.Option(r"([A-Z]+-\d+)$", help="Regex pattern"),
    db: str = typer.Option("tickets.db", help="SQLite DB path"),
    table: str = typer.Option("tickets", help="Table name"),
    debug: bool = typer.Option(False, help="Enable debug")
):
    """Upload attachments to Jira tickets."""
    args = [
        "--dir", dir,
        "--excel", excel,
        "--url", url,
        "--token", token,
        "--sheet", sheet,
        "--id_col", id_col,
        "--evidence_col", evidence_col,
        "--pattern", pattern,
        "--db", db,
        "--table", table
    ]
    if debug:
        args.append("--debug")
    run_script("bulk_attachment_sync.py", args)

@app.command()
def delete(
    excel: str = typer.Argument(..., help="Excel file path"),
    url: str = typer.Argument(..., help="Jira URL"),
    token: str = typer.Argument(..., help="Jira token"),
    sheet: str = typer.Option("0", help="Sheet name or index"),
    id_col: str = typer.Option("ticket_id", help="ID column"),
    db: str = typer.Option("tickets.db", help="SQLite DB path"),
    table: str = typer.Option("tickets", help="Table name"),
    debug: bool = typer.Option(False, help="Enable debug")
):
    """Delete Jira tickets."""
    args = [
        "--excel", excel,
        "--url", url,
        "--token", token,
        "--sheet", sheet,
        "--id_col", id_col,
        "--db", db,
        "--table", table
    ]
    if debug:
        args.append("--debug")
    run_script("bulk_delete_sync.py", args)

@app.command()
def sync(
    excel: str = typer.Argument(..., help="Excel file path"),
    db: str = typer.Argument(..., help="SQLite DB path"),
    table: str = typer.Option("tickets", help="Table name"),
    sheet: str = typer.Option("0", help="Sheet name or index"),
    direction: str = typer.Option("both", help="Sync direction (excel-to-db, db-to-excel, both)")
):
    """Sync Excel and SQLite in either direction."""
    args = [
        "--excel", excel,
        "--db", db,
        "--table", table,
        "--sheet", sheet,
        "--direction", direction
    ]
    run_script("sync_excel_sqlite.py", args)

if __name__ == "__main__":
    app() 