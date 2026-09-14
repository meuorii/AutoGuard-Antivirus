import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

SCRIPT_EXTENSIONS = frozenset({".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".py", ".sh"})
EXECUTABLE_EXTENSIONS = frozenset({".exe", ".scr", ".com", ".pif", ".cpl", ".hta"})
RUNNABLE_EXTENSIONS = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS | {".msi", ".dll", ".lnk"}
DISGUISE_EXTENSIONS = frozenset({".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar"})

@dataclass(frozen=True)
class RuleContext:
    path: Path; script_text: str

@dataclass(frozen=True)
class RuleMatch:
    rule_name: str; reason: str; confidence: float

    def __post_init__(self) -> None:
        if not 0.0 < self.confidence < 1.0: raise ValueError("Heuristic scores must be greater than 0 and below 1.")

DetectionRule = Callable[[RuleContext], RuleMatch | None]

def decode_script_preview(preview: bytes) -> str:
    return preview.decode("utf-16" if preview.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig", errors="replace")

def double_extension_rule(context: RuleContext) -> RuleMatch | None:
    suffixes = [suffix.lower() for suffix in context.path.suffixes]
    if len(suffixes) >= 2 and suffixes[-1] in RUNNABLE_EXTENSIONS and any(suffix in DISGUISE_EXTENSIONS for suffix in suffixes[:-1]):
        return RuleMatch("double_extension", "A document, image, or archive extension precedes a runnable extension.", 0.60)
    return None

def suspicious_filename_rule(context: RuleContext) -> RuleMatch | None:
    if re.search(r"(?:^|[ ._-])(?:keygen|crack|password[ _-]?stealer|credential[ _-]?stealer)(?:$|[ ._-])", context.path.stem, re.IGNORECASE):
        return RuleMatch("suspicious_filename", "The filename contains a suspicious keyword.", 0.45)
    return None

SCRIPT_PATTERNS = (
    ("script_encoded_powershell", r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,256}?-(?:enc|encodedcommand)\b", "Script text invokes PowerShell with an encoded command."),
    ("script_download_pipe", r"\b(?:curl|wget)\b[^\r\n]{0,256}\|\s*(?:sh|bash)\b", "Script text combines a download command with a shell pipeline."),
    ("script_decoded_execution", r"\b(?:exec|eval)\s*\([^\r\n]{0,256}\b(?:b64decode|base64)\b", "Script text combines dynamic execution with Base64 decoding."),
    ("script_powershell_download_execution", r"\b(?:iex|invoke-expression)\b[^\r\n]{0,256}\b(?:downloadstring|iwr|invoke-webrequest)\b", "Script text combines PowerShell dynamic execution and download indicators."),
)

def suspicious_script_rule(context: RuleContext) -> RuleMatch | None:
    for rule_name, pattern, reason in SCRIPT_PATTERNS:
        if re.search(pattern, context.script_text, re.IGNORECASE):
            return RuleMatch(rule_name, reason + " This is a heuristic match.", 0.65)
    return None

def executable_extension_rule(context: RuleContext) -> RuleMatch | None:
    if context.path.suffix.lower() in EXECUTABLE_EXTENSIONS:
        return RuleMatch("executable_extension", "The extension identifies a potentially executable file; it may be legitimate.", 0.35)
    return None

DEFAULT_RULES: tuple[DetectionRule, ...] = (double_extension_rule, suspicious_filename_rule, suspicious_script_rule, executable_extension_rule)