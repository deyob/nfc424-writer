"""CLI entry point — `nfc424-writer`.

Comandi:
  list-readers     # elenca lettori PCSC visibili
  info             # legge UID e versione di un tag sul reader
  program <csv>    # batch program da CSV
  program-one      # un singolo tag (parametri da riga di comando)
  verify <csv>     # rileggi i tag e controlla che corrispondano al CSV
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from .ntag424 import (
    FACTORY_KEY,
    KEY_APP0,
    KEY_APP2,
    Ntag424,
    NtagError,
)
from .reader import Reader, ReaderError
from .sdm import build_ndef_for_url, build_sdm_file_settings
from .source.csv_source import CsvSource
from .source.base import TagJob

app = typer.Typer(help="Writer per tag NTAG 424 DNA via lettore ACR1552U/ACR122U.")
console = Console()


# ---------------------------------------------------------------------------
# Comandi utility
# ---------------------------------------------------------------------------


@app.command("list-readers")
def list_readers_cmd() -> None:
    """Elenca i lettori PCSC collegati."""
    r = Reader()
    names = r.list_readers()
    if not names:
        console.print("[red]Nessun lettore PCSC trovato.[/red]")
        raise typer.Exit(code=1)
    t = Table(title="Lettori PCSC")
    t.add_column("#", justify="right")
    t.add_column("Nome")
    for i, n in enumerate(names):
        t.add_row(str(i), n)
    console.print(t)


@app.command("info")
def info_cmd(
    reader_name: Optional[str] = typer.Option(
        None, "--reader", "-r", help="Sottostringa del nome lettore (es. 'ACR1552')"
    ),
    timeout: float = typer.Option(15.0, "--timeout", "-t", help="Timeout attesa tag (s)"),
) -> None:
    """Presenta un tag sul reader e ne mostra UID + versione."""
    with Reader(name_substr=reader_name, timeout=timeout) as rd:
        console.print(f"[dim]Lettore:[/dim] {rd.reader_name}")
        console.print("[yellow]Appoggia il tag sul lettore...[/yellow]")
        tag = rd.wait_for_tag()
        console.print(f"[green]UID:[/green] {tag.uid.hex().upper()}")
        console.print(f"[dim]ATR:[/dim] {tag.atr}")
        # GetVersion NXP
        n = Ntag424(rd)
        try:
            n.select_ndef_application()
            version = n.get_version()
            console.print(f"[dim]GetVersion ({len(version)} byte):[/dim] {version.hex().upper()}")
        except NtagError as e:
            console.print(f"[red]Errore GetVersion:[/red] {e}")


# ---------------------------------------------------------------------------
# Programmazione
# ---------------------------------------------------------------------------


def _program_single(
    rd: Reader,
    job: TagJob,
    current_app0_key: bytes = FACTORY_KEY,
    current_app2_key: bytes = FACTORY_KEY,
    change_app0_too: bool = False,
    new_app0_key: bytes | None = None,
) -> str:
    """Esegue il ciclo completo di programmazione di UN tag.

    Ritorna l'UID come hex string.

    Sequenza:
      1. SELECT NDEF app
      2. GetUID
      3. WriteData NDEF (file 02, modalità plain, l'accesso è free di default)
      4. AuthEV2First con AppKey0 (factory 00..00 su tag vergine)
      5. ChangeFileSettings su file 02 con SDM abilitato + offset mirror
      6. ChangeKey AppKey2 da factory alla secret_key del CSV
      7. (opzionale) ChangeKey AppKey0 a nuova master — SCONSIGLIATO senza backup
      8. Done
    """
    n = Ntag424(rd)

    # 1. Select NDEF application
    n.select_ndef_application()

    # 2. UID (già letto da wait_for_tag ma riletto via Get Data PC/SC)
    uid_resp, sw1, sw2 = rd.connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
    if (sw1, sw2) != (0x90, 0x00):
        raise NtagError(f"Impossibile rileggere UID: SW={sw1:02X}{sw2:02X}")
    uid_hex = bytes(uid_resp).hex().upper()

    # 3. Costruisci NDEF e scrivi (plain, free access su tag vergine)
    ndef_bytes, mirrors = build_ndef_for_url(job.url_template)
    if len(ndef_bytes) > 256:
        raise NtagError(f"NDEF troppo lungo: {len(ndef_bytes)} byte (max 256)")
    n.write_ndef(ndef_bytes)

    # 4. Auth con AppKey0
    n.authenticate_ev2_first(KEY_APP0, current_app0_key)

    # 5. ChangeFileSettings — abilita SDM + mirror offset
    settings = build_sdm_file_settings(mirrors)
    n.change_file_settings(0x02, settings)

    # 6. ChangeKey AppKey2 (current session auth è su AppKey0 = diverso target
    #    → payload include XOR e CRC32 della nuova chiave)
    new_k2 = job.secret_key_bytes()
    n.change_key(
        target_key_no=KEY_APP2,
        new_key=new_k2,
        old_key=current_app2_key,
        key_version=0x01,
    )

    # 7. Opzionale: cambia anche AppKey0 (master)
    if change_app0_too and new_app0_key is not None:
        n.change_key(
            target_key_no=KEY_APP0,
            new_key=new_app0_key,
            old_key=current_app0_key,
            key_version=0x01,
        )

    return uid_hex


@app.command("program")
def program_cmd(
    csv_path: Path = typer.Argument(..., exists=True, readable=True, help="Batch CSV"),
    reader_name: Optional[str] = typer.Option(
        None, "--reader", "-r", help="Sottostringa del nome lettore"
    ),
    skip_confirm: bool = typer.Option(
        False, "--yes", "-y", help="Non chiedere conferma tra un tag e l'altro"
    ),
    timeout: float = typer.Option(60.0, "--timeout", "-t", help="Timeout attesa tag (s)"),
) -> None:
    """Programma in batch tutti i tag del CSV.

    Il CSV viene aggiornato inline con le colonne di stato (`uid`,
    `programmed_at`, `status`, `error`). Le righe già marcate `status=ok`
    vengono saltate, quindi si può interrompere e riprendere.
    """
    src = CsvSource(csv_path)
    jobs = list(src.iter_jobs())
    if not jobs:
        console.print("[yellow]Nessun tag da programmare (tutti già ok).[/yellow]")
        return

    console.print(f"[bold]Tag da programmare:[/bold] {len(jobs)}")
    console.print(
        "[dim]Il CSV verrà aggiornato con lo stato di ogni tag mentre procedi.[/dim]\n"
    )

    with Reader(name_substr=reader_name, timeout=timeout) as rd:
        console.print(f"[dim]Lettore:[/dim] {rd.reader_name}\n")

        for i, job in enumerate(jobs, start=1):
            console.rule(f"[bold]Tag {i}/{len(jobs)}: {job.label or job.short_code}")
            console.print(f"  short_code = {job.short_code}")
            console.print(f"  URL        = {job.url_template}")
            if not skip_confirm:
                if not Confirm.ask("Appoggia il tag vergine sul lettore e premi invio"):
                    console.print("[yellow]Skip.[/yellow]")
                    continue

            try:
                console.print("[dim]Attesa tag...[/dim]")
                rd.wait_for_tag()
                uid = _program_single(rd, job)
                src.mark_done(job, uid_hex=uid)
                console.print(f"[green]✓ OK[/green] UID={uid}")
            except (NtagError, ReaderError) as e:
                console.print(f"[red]✗ Errore:[/red] {e}")
                src.mark_error(job, str(e))

            # Aspetta rimozione del tag prima di chiedere il prossimo
            console.print("[dim]Rimuovi il tag dal lettore.[/dim]")
            rd.wait_for_tag_removed()

    console.rule("[bold]Fine")
    console.print(f"CSV aggiornato: {csv_path}")


@app.command("program-one")
def program_one_cmd(
    short_code: str = typer.Option(..., "--short-code", "-s"),
    secret_key: str = typer.Option(..., "--key", "-k", help="AppKey2 in hex (32 char)"),
    url_template: str = typer.Option(
        ...,
        "--url",
        "-u",
        help='URL con placeholder, es. "https://shoprfid.it/t/XYZ?picc_data={UID_COUNTER}&cmac={CMAC}"',
    ),
    label: str = typer.Option("", "--label", "-l"),
    reader_name: Optional[str] = typer.Option(None, "--reader", "-r"),
    timeout: float = typer.Option(30.0, "--timeout", "-t"),
) -> None:
    """Programma un singolo tag senza CSV (parametri da riga di comando)."""
    if len(secret_key) != 32:
        raise typer.BadParameter("secret_key deve essere 32 caratteri hex (16 byte)")
    try:
        bytes.fromhex(secret_key)
    except ValueError as e:
        raise typer.BadParameter(f"secret_key non è hex valido: {e}") from e

    job = TagJob(
        short_code=short_code,
        secret_key_hex=secret_key,
        label=label,
        url_template=url_template,
        plain_url="",
    )

    with Reader(name_substr=reader_name, timeout=timeout) as rd:
        console.print(f"[dim]Lettore:[/dim] {rd.reader_name}")
        console.print(f"[yellow]Appoggia il tag {short_code}...[/yellow]")
        rd.wait_for_tag()
        try:
            uid = _program_single(rd, job)
            console.print(f"[green]✓ Programmato[/green] UID={uid}")
        except (NtagError, ReaderError) as e:
            console.print(f"[red]✗ Errore:[/red] {e}")
            raise typer.Exit(code=1) from e


if __name__ == "__main__":
    app()
