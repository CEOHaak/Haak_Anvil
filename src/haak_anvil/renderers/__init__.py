from haak_anvil.renderers.base import RendererBase
from haak_anvil.renderers.docx_renderer import DocxRenderer
from haak_anvil.renderers.html import HtmlRenderer
from haak_anvil.renderers.json_renderer import JsonRenderer
from haak_anvil.renderers.markdown import MarkdownRenderer

__all__ = ["DocxRenderer", "HtmlRenderer", "JsonRenderer", "MarkdownRenderer", "RendererBase"]


def get_renderer(format_name: str) -> type[RendererBase]:
    """Factory: 'json' / 'md' / 'html' / 'docx' -> class."""
    table: dict[str, type[RendererBase]] = {
        "json": JsonRenderer,
        "md": MarkdownRenderer,
        "markdown": MarkdownRenderer,
        "html": HtmlRenderer,
        "docx": DocxRenderer,
        "word": DocxRenderer,
    }
    fmt = format_name.lower()
    if fmt not in table:
        raise ValueError(
            f"Unknown format {format_name!r}; choose from {sorted(table)}"
        )
    return table[fmt]
