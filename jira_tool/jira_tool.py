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
def create(args: typer.Argument(..., help="Arguments for bulk_create_sync.py", nargs=-1)):
    """Bulk create Jira tickets."""
    run_script("bulk_create_sync.py", list(args))

@app.command()
def update(args: typer.Argument(..., help="Arguments for bulk_update_sync.py", nargs=-1)):
    """Bulk update Jira tickets."""
    run_script("bulk_update_sync.py", list(args))

@app.command()
def comment(args: typer.Argument(..., help="Arguments for bulk_comment_sync.py", nargs=-1)):
    """Bulk add comments to Jira tickets."""
    run_script("bulk_comment_sync.py", list(args))

@app.command()
def status(args: typer.Argument(..., help="Arguments for bulk_status_sync.py", nargs=-1)):
    """Fetch Jira ticket status."""
    run_script("bulk_status_sync.py", list(args))

@app.command()
def transition(args: typer.Argument(..., help="Arguments for bulk_transition_sync.py", nargs=-1)):
    """Change Jira ticket status."""
    run_script("bulk_transition_sync.py", list(args))

@app.command()
def attach(args: typer.Argument(..., help="Arguments for bulk_attachment_sync.py", nargs=-1)):
    """Upload attachments to Jira tickets."""
    run_script("bulk_attachment_sync.py", list(args))

@app.command()
def delete(args: typer.Argument(..., help="Arguments for bulk_delete_sync.py", nargs=-1)):
    """Delete Jira tickets."""
    run_script("bulk_delete_sync.py", list(args))

@app.command()
def sync(args: typer.Argument(..., help="Arguments for sync_excel_sqlite.py", nargs=-1)):
    """Sync Excel and SQLite in either direction."""
    run_script("sync_excel_sqlite.py", list(args))

if __name__ == "__main__":
    app() 