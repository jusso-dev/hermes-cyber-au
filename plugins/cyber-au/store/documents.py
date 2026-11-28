"""Plain documents for people: markdown on screen, xlsx and docx on disk.

The evidence register, the gap report and the executive reports build one ``Document``
(headings, paragraphs, bullets, tables) and render it here, so the markdown and the docx
always say the same thing.

openpyxl and python-docx are an optional extra. Install them with
``uv sync --project mcp --extra documents``. Without them, markdown still works and the
file exports raise :class:`DocumentsUnavailable` with that install hint.

Files are written only under ``plugin-data/cyber-au/exports/``. Nothing here sends,
uploads or posts a file.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass, field
from pathlib import Path

INSTALL_HINT = (
    "xlsx and docx export needs the optional documents extra: "
    "run uv sync --project mcp --extra documents"
)
# A spreadsheet treats a cell that starts with one of these as a formula.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


class DocumentsUnavailable(RuntimeError):
    """Raised when openpyxl or python-docx is not installed."""


def _load(module: str):
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        raise DocumentsUnavailable(INSTALL_HINT) from exc


def load_openpyxl():
    """Import ``openpyxl`` or raise :class:`DocumentsUnavailable` with the install hint."""
    return _load("openpyxl")


def load_docx():
    """Import ``docx`` (python-docx) or raise :class:`DocumentsUnavailable`."""
    return _load("docx")


@dataclass
class Block:
    kind: str  # heading, para, bullet, table
    text: str = ""
    level: int = 2
    rows: list[list[str]] = field(default_factory=list)


@dataclass
class Document:
    title: str
    blocks: list[Block] = field(default_factory=list)

    def heading(self, text: str, level: int = 2) -> None:
        self.blocks.append(Block("heading", text=text, level=level))

    def para(self, text: str) -> None:
        self.blocks.append(Block("para", text=text))

    def bullet(self, text: str) -> None:
        self.blocks.append(Block("bullet", text=text))

    def table(self, header: list[str], rows: list[list[object]]) -> None:
        body = [[_cell_text(value) for value in row] for row in rows]
        self.blocks.append(Block("table", rows=[list(header), *body]))


@dataclass
class Sheet:
    title: str
    header: list[str]
    rows: list[list[object]]
    widths: dict[int, int] = field(default_factory=dict)


def to_markdown(document: Document) -> str:
    out = [f"# {document.title}", ""]
    previous = ""
    for block in document.blocks:
        if block.kind != "bullet" and previous == "bullet":
            out.append("")
        if block.kind == "heading":
            out += [f"{'#' * max(2, min(block.level, 4))} {block.text}", ""]
        elif block.kind == "para":
            out += [block.text, ""]
        elif block.kind == "bullet":
            out.append(f"- {block.text}")
        elif block.kind == "table":
            header, *rows = block.rows
            out.append("| " + " | ".join(_md_cell(item) for item in header) + " |")
            out.append("|" + "|".join("---" for _ in header) + "|")
            for row in rows:
                out.append("| " + " | ".join(_md_cell(item) for item in row) + " |")
            out.append("")
        previous = block.kind
    return "\n".join(out).rstrip() + "\n"


def write_docx(document: Document, requested: str, store: str | Path | None = None) -> str:
    """Write ``document`` as a .docx under exports and return the path relative to the data dir."""
    docx = load_docx()
    destination = _destination(requested, store, ".docx")
    word = docx.Document()
    word.core_properties.title = document.title
    word.add_heading(document.title, level=0)
    for block in document.blocks:
        if block.kind == "heading":
            word.add_heading(block.text, level=max(1, min(block.level - 1, 3)))
        elif block.kind == "para":
            word.add_paragraph(block.text)
        elif block.kind == "bullet":
            word.add_paragraph(block.text, style="List Bullet")
        elif block.kind == "table":
            header, *rows = block.rows
            table = word.add_table(rows=1, cols=len(header))
            table.style = "Table Grid"
            for index, item in enumerate(header):
                cell = table.rows[0].cells[index]
                cell.text = item
                for run in cell.paragraphs[0].runs:
                    run.bold = True
            for row in rows:
                cells = table.add_row().cells
                for index, item in enumerate(row):
                    cells[index].text = item
    return _save(destination, store, word.save)


def write_xlsx(sheets: list[Sheet], requested: str, store: str | Path | None = None) -> str:
    """Write ``sheets`` as one .xlsx under exports and return the relative path."""
    openpyxl = load_openpyxl()
    styles = importlib.import_module("openpyxl.styles")
    destination = _destination(requested, store, ".xlsx")
    book = openpyxl.Workbook()
    book.remove(book.active)
    for sheet in sheets:
        page = book.create_sheet(title=sheet.title[:31])
        page.append(list(sheet.header))
        for cell in page[1]:
            cell.font = styles.Font(bold=True)
        for row in sheet.rows:
            page.append([None for _ in row])
            for column, value in enumerate(row, start=1):
                _set_cell(page.cell(row=page.max_row, column=column), value)
        page.freeze_panes = "A2"
        for column, width in sheet.widths.items():
            letter = openpyxl.utils.get_column_letter(column)
            page.column_dimensions[letter].width = width
            for cell in page[letter]:
                cell.alignment = styles.Alignment(wrap_text=True, vertical="top")
    return _save(destination, store, book.save)


def _set_cell(cell, value: object) -> None:
    """Write a value so text from the register can never become a formula."""
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int | float):
        text = _cell_text(value)
        cell.value = text
        cell.data_type = "s"
        if text.startswith(_FORMULA_START):
            cell.quotePrefix = True
        return
    cell.value = value


def _cell_text(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _destination(requested: str, store: str | Path | None, suffix: str) -> Path:
    from .db import store_data_dir
    from .stix import resolve_export_path

    destination = resolve_export_path(requested, store, suffix=suffix)
    raw = Path(requested)
    candidate = raw if raw.is_absolute() else store_data_dir(store) / "exports" / raw
    if candidate.is_symlink() or destination.is_symlink():
        raise ValueError("refusing to write through a symlink")
    return destination


def _save(destination: Path, store: str | Path | None, save) -> str:
    from .db import store_data_dir

    partial = destination.with_name(destination.name + ".partial")
    if partial.is_symlink():
        raise ValueError("refusing to write through a symlink")
    partial.unlink(missing_ok=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with partial.open("xb") as handle:
            save(handle)
        os.replace(partial, destination)
    except BaseException:
        if not partial.is_symlink():
            partial.unlink(missing_ok=True)
        raise
    return destination.relative_to(store_data_dir(store).resolve()).as_posix()


__all__ = [
    "INSTALL_HINT",
    "Block",
    "Document",
    "DocumentsUnavailable",
    "Sheet",
    "load_docx",
    "load_openpyxl",
    "to_markdown",
    "write_docx",
    "write_xlsx",
]
