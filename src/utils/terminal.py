"""Interactive terminal helpers shared across queriers."""

from rich.console import Console

console = Console()


def confirm_exit() -> bool:
    """Ask the analyst to confirm exit via CTRL+C. Returns True if confirmed."""
    console.print(
        "\n  [bold red]CTRL+C[/bold red] again to exit / [bold green]Enter[/bold green] to continue",
        end=" ",
    )
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        print()
        return True
    return False


def prompt(text: str) -> str:
    """input() wrapper: returns empty string on EOF, re-raises KeyboardInterrupt."""
    try:
        return input(text)
    except EOFError:
        return ""
    except KeyboardInterrupt:
        console.print("")  # move off the input line
        raise
