import asyncio
import shutil
import sys

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.status import Status

from russiafancylists.config import (
    CUSTOM_FOLDER,
    GEOBLOCK_FOLDER,
    HOSTS_LIST_FOLDER,
    LIST_FOLDER,
    ROOT_DIR,
    TEMP_FOLDER,
)
from russiafancylists.downloader import run_downloads
from russiafancylists.hosts import (
    generate_aligned_hosts,
    parse_zapret_sh,
)
from russiafancylists.processors import (
    cleanup_domains,
    merge_lists,
)
from russiafancylists.status import (
    update_readme_hosts_links,
    update_readme_sizes,
    update_readme_status,
)

console = Console()


def setup_dirs(skip_download: bool = False):
    """Clear lists folder files and ensure all output folders exist, robustly handling locked directories on Windows."""
    if LIST_FOLDER.exists():
        from russiafancylists.config import DOWNLOADS

        # Find direct output files defined in DOWNLOADS that should not be deleted during skip-download mode
        download_targets = {
            target_path.resolve() for _, target_path, _ in DOWNLOADS.values()
        }

        # Clear existing files and directories
        for item in LIST_FOLDER.iterdir():
            if item.resolve() == HOSTS_LIST_FOLDER.resolve():
                continue
            if skip_download and item.resolve() in download_targets:
                continue
            try:
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink(missing_ok=True)
            except Exception:
                pass

    # Ensure all directories exist
    for folder in [
        CUSTOM_FOLDER,
        TEMP_FOLDER / "hosts",
        HOSTS_LIST_FOLDER,
        GEOBLOCK_FOLDER,
    ]:
        folder.mkdir(parents=True, exist_ok=True)


def cleanup():
    """Remove temp folder and resume configurations."""
    resume_cfg = ROOT_DIR / "resume.cfg"
    if resume_cfg.exists():
        resume_cfg.unlink()
    if TEMP_FOLDER.exists():
        shutil.rmtree(TEMP_FOLDER)


async def run_pipeline(
    skip_download: bool = False,
    keep_temp: bool = False,
):
    """Run all steps of the update pipeline concurrently, matching original Bash parallelism."""
    try:
        # Silence harmless Windows ProactorEventLoop ConnectionResetError (WinError 10054)
        if sys.platform == "win32":
            loop = asyncio.get_running_loop()
            orig_handler = loop.get_exception_handler()

            def silence_winerror_10054(_loop, context):
                exc = context.get("exception")
                if (
                    isinstance(exc, ConnectionResetError)
                    and getattr(exc, "winerror", None) == 10054
                ):
                    return
                if orig_handler:
                    orig_handler(_loop, context)
                else:
                    _loop.default_exception_handler(context)

            loop.set_exception_handler(silence_winerror_10054)

        setup_dirs(skip_download=skip_download)

        # --- Stage 1: Async Downloads ---
        if not skip_download:
            console.print(
                "[bold purple]Stage 1: Downloading source lists...[/bold purple]"
            )
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console,
            )
            with progress:
                await run_downloads(progress)
        else:
            console.print(
                "[bold purple]Stage 1: Skipping download stage (using local temp files)...[/bold purple]"
            )

        # --- Stage 2: Merging ---
        console.print("\n[bold purple]Stage 2: Merging lists...[/bold purple]")
        with Status(
            "[cyan]Parsing shell scripts and merging domains...", console=console
        ) as status:
            # 0. Parse downloaded Zapret-Manager.sh file into a standard hosts-formatted .lst file
            if (TEMP_FOLDER / "zapret-manager.sh").exists():
                await asyncio.to_thread(
                    parse_zapret_sh,
                    TEMP_FOLDER / "zapret-manager.sh",
                    TEMP_FOLDER / "hosts" / "zapret-manager-parsed.lst",
                )
            elif (TEMP_FOLDER / "hosts" / "zapret-manager-parsed.lst").exists():
                console.print(
                    "[yellow]⚠ Zapret-Manager.sh not found; reusing cached parsed list[/yellow]"
                )
            else:
                console.print(
                    "[yellow]⚠ Zapret-Manager.sh not found, skipping its parsing[/yellow]"
                )

            # Copy custom lists into temp hosts folder if available
            if CUSTOM_FOLDER.exists():
                for custom_file in CUSTOM_FOLDER.glob("*.lst"):
                    shutil.copy2(
                        custom_file,
                        TEMP_FOLDER / "hosts" / f"custom-{custom_file.name}",
                    )

            # 1. Merge geoblock lists (acting as base for hosts lists)
            await asyncio.to_thread(
                merge_lists,
                TEMP_FOLDER / "hosts",
                GEOBLOCK_FOLDER / "full.lst",
                file_pattern="*.lst",
            )

        with Status(
            "[cyan]Building aligned hosts files from full geoblock list...",
            console=console,
        ) as status:
            # 2. Build aligned hosts files from the completed full geoblock list
            await generate_aligned_hosts(
                GEOBLOCK_FOLDER / "full.lst",
                TEMP_FOLDER / "hosts",
                HOSTS_LIST_FOLDER,
            )
            status.update(
                "[green]✓ Domains, Geoblocks, and aligned Hosts compiled successfully[/green]"
            )

        # --- Stage 3: Dependent Processing ---
        console.print("\n[bold purple]Stage 3: Dependent processing...[/bold purple]")
        with Status(
            "[cyan]Filtering domains and updating tables...",
            console=console,
        ) as status:
            await asyncio.to_thread(
                cleanup_domains,
                GEOBLOCK_FOLDER / "full.lst",
                GEOBLOCK_FOLDER / "full-sld.lst",
            )
            status.update(
                "[cyan]Measuring Smart DNS proxy latencies and updating README status..."
            )
            await update_readme_status(TEMP_FOLDER / "hosts", ROOT_DIR)
            status.update("[cyan]Updating README hosts links tables...")
            await update_readme_hosts_links(ROOT_DIR, HOSTS_LIST_FOLDER)
            status.update("[cyan]Updating README file size tables...")
            await update_readme_sizes(ROOT_DIR)
            status.update(
                "[green]✓ Dependent processing and status checks completed[/green]"
            )

        console.print("\n[bold green]✓ Process completed successfully![/bold green]")

    except Exception as e:
        console.print(f"\n[bold red]✗ Process failed: {e}[/bold red]")
        sys.exit(1)
    finally:
        if not keep_temp:
            cleanup()
        else:
            resume_cfg = ROOT_DIR / "resume.cfg"
            if resume_cfg.exists():
                resume_cfg.unlink()
