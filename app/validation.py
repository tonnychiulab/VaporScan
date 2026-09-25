"""Content validation — never trusts the filename extension alone.

Everything here operates on an in-memory ``bytes`` object. Nothing is
ever written to disk, per the "data never lands" (資料不落地) requirement.
"""
import io
import zipfile
from dataclasses import dataclass

from app.config import Settings
from app.errors import CorruptOrUnreadableError, InvalidFileTypeError, SuspiciousArchiveError

PDF_MAGIC = b"%PDF-"
ZIP_MAGIC = b"PK\x03\x04"
DOCX_CONTENT_TYPES_ENTRY = "[Content_Types].xml"


@dataclass(frozen=True)
class DetectedType:
    extension: str  # ".pdf" or ".docx"
    mime: str


def detect_and_validate(filename: str, content: bytes, settings: Settings) -> DetectedType:
    """Validates the *actual* bytes, not just the filename suffix.

    Raises InvalidFileTypeError / CorruptOrUnreadableError / SuspiciousArchiveError.
    """
    claimed_ext = _extension_of(filename)
    if claimed_ext not in settings.allowed_extensions:
        raise InvalidFileTypeError(f"不支援的檔案格式：{claimed_ext or '(無副檔名)'}")

    if content.startswith(PDF_MAGIC):
        if claimed_ext != ".pdf":
            raise InvalidFileTypeError("副檔名與實際內容不符（偵測為 PDF）")
        return DetectedType(extension=".pdf", mime="application/pdf")

    if content.startswith(ZIP_MAGIC):
        _validate_docx_zip(content, settings)
        if claimed_ext != ".docx":
            raise InvalidFileTypeError("副檔名與實際內容不符（偵測為 DOCX/ZIP）")
        return DetectedType(
            extension=".docx",
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )

    raise InvalidFileTypeError("無法辨識的檔案內容，非有效的 PDF 或 DOCX")


def _extension_of(filename: str) -> str:
    idx = filename.rfind(".")
    return filename[idx:].lower() if idx != -1 else ""


def _validate_docx_zip(content: bytes, settings: Settings) -> None:
    """Confirms this is a real OOXML package and guards against zip bombs.

    zipfile's central directory already carries compressed/uncompressed
    sizes for every entry, so the ratio check below costs nothing extra —
    it does NOT require actually inflating the entries.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            names = zf.namelist()
            if DOCX_CONTENT_TYPES_ENTRY not in names:
                raise CorruptOrUnreadableError("非有效的 DOCX 套件（缺少 [Content_Types].xml）")

            total_uncompressed = 0
            total_compressed = 0
            for info in zf.infolist():
                total_uncompressed += info.file_size
                total_compressed += info.compress_size

            total_uncompressed_mb = total_uncompressed / (1024 * 1024)
            if total_uncompressed_mb > settings.zip_max_uncompressed_total_mb:
                raise SuspiciousArchiveError(
                    f"解壓縮後總大小 {total_uncompressed_mb:.1f}MB 超過上限 "
                    f"{settings.zip_max_uncompressed_total_mb}MB，疑似 Zip Bomb"
                )

            if total_compressed > 0:
                ratio = total_uncompressed / total_compressed
                if ratio > settings.zip_max_decompression_ratio:
                    raise SuspiciousArchiveError(
                        f"解壓縮比 {ratio:.0f}:1 超過上限 "
                        f"{settings.zip_max_decompression_ratio}:1，疑似 Zip Bomb"
                    )
    except zipfile.BadZipFile as exc:
        raise CorruptOrUnreadableError("檔案內容無法讀取（非有效的 ZIP/DOCX 結構）") from exc
