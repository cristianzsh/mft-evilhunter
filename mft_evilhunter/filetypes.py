"""
File type knowledge: extension sets and content signatures.
"""

from __future__ import annotations

from typing import Optional, Set, Tuple

# Anything that can execute or be executed by an interpreter.
EXECUTABLE_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".bat", ".cmd",
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".msi", ".msp", ".cpl", ".ocx", ".jar", ".lnk",
}

# Wrappers used to deliver payloads
DOWNLOAD_CONTAINER_EXTENSIONS: Set[str] = {
    ".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx", ".cab", ".ace",
    ".gz", ".tar", ".bz2", ".xz", ".lzh", ".arj",
}

# Document types commonly used as the lure in a phishing chain
DOCUMENT_EXTENSIONS: Set[str] = {
    ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx",
    ".pptm", ".rtf", ".pdf", ".one", ".pub",
}


# Content signatures

# Magic bytes, label, and the extensions that legitimately carry them. A file
# whose resident content disagrees with its extension is masquerading.
CONTENT_SIGNATURES: Tuple[Tuple[bytes, str, Set[str]], ...] = (
    (b"MZ", "PE executable", {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".mui",
                              ".efi", ".drv", ".tsp", ".ax", ".node", ".acm", ".com",
                              ".msstyles", ".tlb", ".winmd", ".rll", ".dat"}),
    (b"PK\x03\x04", "ZIP container", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk",
                                      ".appx", ".nupkg", ".vsix", ".odt", ".ods",
                                      ".crx", ".whl", ".epub", ".xpi", ".kmz"}),
    (b"\x7fELF", "ELF executable", {".so", ".elf", ".o", ".bin"}),
    (b"%PDF", "PDF", {".pdf"}),
    (b"\xd0\xcf\x11\xe0", "OLE compound file", {".doc", ".xls", ".ppt", ".msi", ".msg",
                                                ".db", ".vsd", ".jse", ".dat", ".wiz"}),
    (b"\x89PNG", "PNG", {".png"}),
    (b"\xff\xd8\xff", "JPEG", {".jpg", ".jpeg", ".jfif"}),
    (b"GIF8", "GIF", {".gif"}),
    (b"Rar!", "RAR archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {".7z"}),
    (b"#!", "script shebang", {".sh", ".py", ".pl", ".rb", "", ".bash"}),
    (b"<?xml", "XML", {".xml", ".xaml", ".manifest", ".config", ".resx", ".svg",
                       ".rels", ".vcxproj", ".csproj", ".props", ".targets", ".mum",
                       ".dat", ".library-ms", ".job", ".admx", ".adml",
                       ".search-ms", ".searchconnector-ms", ".settingcontent-ms",
                       ".appxmanifest", ".nuspec", ".ps1xml", ".msc", ".wsf",
                       ".xsx", ".xsd", ".xslt", ".xsl", ".vstemplate", ".addin",
                       ".diagpkg", ".diagcfg", ".xrm-ms", ".rdl", ".gpd"}),
    (b"<!DOCTYPE html", "HTML", {".html", ".htm", ".hta"}),
    (b"SQLite format 3", "SQLite database", {".db", ".sqlite", ".sqlite3", ".dat", ".edb"}),
)

_PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\r\n"


def detect_content_type(data: bytes):
    """Return (label, allowed_extensions) for resident content, or (None, None)."""
    for magic, label, extensions in CONTENT_SIGNATURES:
        if data.startswith(magic):
            return label, extensions
    return None, None


def content_mismatch(data: bytes, extension: str) -> Optional[str]:
    """Return the content label when it disagrees with the extension."""
    if not data:
        return None
    label, allowed = detect_content_type(data)
    if label and allowed and extension.lower() not in allowed:
        return label
    return None


def resident_preview(data: bytes, limit: int = 160) -> str:
    """A printable excerpt of resident content, for display and searching."""
    if not data:
        return ""
    sample = data[:limit * 3]
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = sample.decode("utf-16", errors="replace")
        except Exception:
            text = ""
    elif sample.count(b"\x00") > len(sample) // 3:
        text = sample.replace(b"\x00", b"").decode("latin-1", errors="replace")
    else:
        text = bytes(c for c in sample if c in _PRINTABLE).decode("latin-1", "replace")
    return " ".join(text.split())[:limit]


# Mark-of-the-Web zones

ZONE_NAMES = {
    "0": "Local machine",
    "1": "Local intranet",
    "2": "Trusted site",
    "3": "Internet",
    "4": "Restricted site",
}

def zone_label(zone_id: str) -> str:
    return ZONE_NAMES.get(str(zone_id).strip(), "")


# Extensions unremarkable anywhere
KNOWN_EXTENSIONS: Set[str] = (
    EXECUTABLE_EXTENSIONS | DOWNLOAD_CONTAINER_EXTENSIONS | DOCUMENT_EXTENSIONS | {
        ".txt", ".log", ".csv", ".tsv", ".xml", ".json", ".yaml", ".yml", ".ini",
        ".cfg", ".config", ".reg", ".inf", ".dat", ".db", ".sqlite", ".sqlite3",
        ".bak", ".old", ".tmp", ".temp", ".swp", ".lock", ".lck", ".pid",
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".ico", ".svg",
        ".webp", ".heic", ".raw", ".psd", ".ai", ".eps",
        ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".wma",
        ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v",
        ".html", ".htm", ".css", ".php", ".asp", ".aspx", ".jsp", ".md", ".rst",
        ".py", ".pyc", ".pyd", ".rb", ".pl", ".go", ".rs", ".java", ".class",
        ".c", ".h", ".cpp", ".hpp", ".cs", ".vb", ".ts", ".tsx", ".jsx", ".map",
        ".lnk", ".url", ".pf", ".etl", ".evtx", ".mui", ".cat", ".mum", ".manifest",
        ".dll", ".sys", ".drv", ".ocx", ".cpl", ".ax", ".tlb", ".winmd", ".rll",
        ".ttf", ".otf", ".woff", ".woff2", ".eot", ".fon",
        ".pem", ".crt", ".cer", ".key", ".pfx", ".p12", ".pub", ".asc",
        ".iso", ".vhd", ".vhdx", ".vmdk", ".ova", ".wim", ".esd",
        ".chm", ".hlp", ".msc", ".theme", ".deskthemepack", ".contact",
        ".eml", ".msg", ".pst", ".ost", ".nk2", ".ics", ".vcf",
        ".resx", ".xsd", ".xsl", ".xslt", ".props", ".targets", ".nuspec",

        # Windows-shipped extensions
        ".cdf-ms", ".xrm-ms", ".inf_loc", ".cdxml", ".mof", ".mfl", ".man",
        ".pri", ".adml", ".admx", ".cur", ".ani", ".mun", ".p7x", ".nls",
        ".xbf", ".pckgdep", ".pak", ".pnf", ".ppkg", ".browser", ".ascx",
        ".catalogitem", ".gpd", ".hyb", ".table", ".vmsg", ".qml", ".qmltypes",
        ".nlp", ".hbakedcurve", ".checkpoint", ".regtrans-ms", ".blf",
        ".jfm", ".jrs", ".chk", ".ese", ".edb", ".dit", ".sdi", ".efi",
        ".aux", ".idx", ".dic", ".lex", ".uce", ".ttc", ".fntdata",
        ".mmc", ".psc1", ".psm", ".cdmp", ".dmp", ".hdmp", ".mdmp",
        ".appref-ms", ".diagpkg", ".diagcfg", ".xrm", ".sqm", ".slc",
        ".rtmp", ".ncb", ".bck", ".ver", ".dpx", ".mzz", ".prm",
        ".ps1xml", ".xaml", ".bin", ".sql", ".data", ".dll_", ".exe_",
    }
)

# Extensions whose tail varies per file. Matched as patterns rather than enumerated
KNOWN_EXTENSION_PATTERNS = (
    r"^\.mui_[0-9a-f]{6,10}$",
    r"^\.log\d{1,3}$",
    r"^\.tmcontainer\d+$",
    r"^\.db-(wal|shm|journal)$",
    r"^\.\d{1,4}$",
    r"^\.part\d*$",
    r"^\.bak\d*$",
)

_KNOWN_PATTERN_RE = None


def is_known_extension(extension: str) -> bool:
    """True for extensions that are unremarkable on a Windows volume."""
    global _KNOWN_PATTERN_RE
    if not extension:
        return True
    extension = extension.lower()
    if extension in KNOWN_EXTENSIONS:
        return True
    if _KNOWN_PATTERN_RE is None:
        import re as _re
        _KNOWN_PATTERN_RE = _re.compile(
            "|".join(f"({p})" for p in KNOWN_EXTENSION_PATTERNS))
    return bool(_KNOWN_PATTERN_RE.match(extension))


# Core process and LOLBin names that only belong in these directories
SYSTEM_BINARY_LOCATIONS = {
    "svchost.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "lsass.exe": ["\\windows\\system32"],
    "csrss.exe": ["\\windows\\system32"],
    "winlogon.exe": ["\\windows\\system32"],
    "services.exe": ["\\windows\\system32"],
    "smss.exe": ["\\windows\\system32"],
    "spoolsv.exe": ["\\windows\\system32"],
    "wininit.exe": ["\\windows\\system32"],
    "taskhostw.exe": ["\\windows\\system32"],
    "dllhost.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "conhost.exe": ["\\windows\\system32"],
    "rundll32.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "regsvr32.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    # A 32-bit explorer.exe ships in SysWOW64 alongside the 64-bit one.
    "explorer.exe": ["\\windows", "\\windows\\syswow64"],
    "cmd.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "powershell.exe": [
        "\\windows\\system32\\windowspowershell\\v1.0",
        "\\windows\\syswow64\\windowspowershell\\v1.0",
    ],
    "wmiprvse.exe": ["\\windows\\system32\\wbem", "\\windows\\syswow64\\wbem"],
    "wmic.exe": ["\\windows\\system32\\wbem", "\\windows\\syswow64\\wbem"],
    "msiexec.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "ctfmon.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "sihost.exe": ["\\windows\\system32"],
    "fontdrvhost.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "dwm.exe": ["\\windows\\system32"],
    "logonui.exe": ["\\windows\\system32"],
    "userinit.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "runtimebroker.exe": ["\\windows\\system32"],
    "searchindexer.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "mshta.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "wscript.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "cscript.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "werfault.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "audiodg.exe": ["\\windows\\system32"],
    "certutil.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "bitsadmin.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "schtasks.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "esentutl.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "ntdsutil.exe": ["\\windows\\system32"],
    "nltest.exe": ["\\windows\\system32", "\\windows\\syswow64"],
    "dsquery.exe": ["\\windows\\system32"],
    "taskhost.exe": ["\\windows\\system32"],
    "lsm.exe": ["\\windows\\system32"],
}

# ARM64 Windows keeps its 32 bit binaries in SysArm32 and SyChpe32 instead of SysWOW64.
SYSWOW64_ALIASES = ("\\windows\\sysarm32", "\\windows\\sychpe32")

# The names an operator renames a payload to in order to blend in.
SYSTEM_BINARY_NAMES = frozenset(SYSTEM_BINARY_LOCATIONS)
