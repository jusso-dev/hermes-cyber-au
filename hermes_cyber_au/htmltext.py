"""Turn a public page into plain text. Scripts and styles are dropped."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from .common import instruction_like, strip_emails

_SKIP = {"script", "style", "noscript", "svg"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip = 0
        self.parts: list[str] = []
        self.links: list[str] = []
        self.title_parts: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        name = tag.lower()
        if name in _SKIP:
            self._skip += 1
        if name == "title":
            self._in_title = True
        if name == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)
        if name in {"p", "div", "h1", "h2", "h3", "li", "br", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        name = tag.lower()
        if name in _SKIP and self._skip:
            self._skip -= 1
        if name == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._in_title:
            self.title_parts.append(data)
        self.parts.append(data)


def html_to_text(raw: str) -> tuple[str, str, list[str]]:
    parser = _TextExtractor()
    parser.feed(raw)
    parser.close()
    title = " ".join(" ".join(parser.title_parts).split())
    text = re.sub(r"[ \t]+", " ", "".join(parser.parts))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return title, strip_emails(text), parser.links


def page_is_usable(text: str) -> bool:
    letters = sum(ch.isalpha() for ch in text)
    return letters >= 400


def chunk_page(text: str, limit: int = 3500) -> list[str]:
    if len(text) <= limit:
        return [text] if text else []
    paragraphs = [part.strip() for part in text.split("\n") if part.strip()]
    chunks: list[str] = []
    current: list[str] = []
    size = 0
    for paragraph in paragraphs:
        if size + len(paragraph) > limit and current:
            chunks.append("\n".join(current))
            current = []
            size = 0
        current.append(paragraph)
        size += len(paragraph) + 1
    if current:
        chunks.append("\n".join(current))
    return chunks


def prepare_text(text: str) -> tuple[str, bool]:
    cleaned = strip_emails(text)
    return cleaned, instruction_like(cleaned)
