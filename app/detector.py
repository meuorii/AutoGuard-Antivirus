from pathlib import Path
from typing import Iterable

from app.detection_rules import DEFAULT_RULES, SCRIPT_EXTENSIONS, DetectionRule, RuleContext, decode_script_preview
from app.hashing import inspect_file
from app.models import DetectionResult, DetectionStatus, FileInspection, SignatureKind
from app.signatures import SignatureStore

SCRIPT_PREVIEW_BYTES = 64 * 1024

class Detector:
    def __init__(self, signatures: SignatureStore, rules: Iterable[DetectionRule] = DEFAULT_RULES) -> None:
        self.signatures = signatures; self.rules = tuple(rules)

    def detect_file(self, path: str | Path) -> DetectionResult:
        is_script = Path(path).suffix.lower() in SCRIPT_EXTENSIONS
        return self.detect_inspection(inspect_file(path, preview_bytes=SCRIPT_PREVIEW_BYTES if is_script else 0))

    def detect_inspection(self, inspection: FileInspection) -> DetectionResult:
        fingerprint = inspection.fingerprint
        is_script = Path(fingerprint.path).suffix.lower() in SCRIPT_EXTENSIONS
        if (signature := self.signatures.lookup(fingerprint.sha256)) is not None:
            is_test = signature.kind is SignatureKind.AUTOGUARD_TEST
            return DetectionResult(
                status=DetectionStatus.HIGH_CONFIDENCE, confidence=1.0,
                reason=("Exact match to the harmless AutoGuard test signature; this is a test detection." if is_test else f"SHA-256 matches known malicious signature: {signature.name}."),
                rule_name="autoguard_test_signature" if is_test else "known_malicious_sha256",
                sha256=fingerprint.sha256, path=fingerprint.path, matched_signature=signature
            )

        context = RuleContext(Path(fingerprint.path), decode_script_preview(inspection.preview))
        if matches := [match for rule in self.rules if (match := rule(context)) is not None]:
            strongest = max(matches, key=lambda match: match.confidence)
            return DetectionResult(
                status=DetectionStatus.LOW_CONFIDENCE, confidence=strongest.confidence,
                reason=strongest.reason, rule_name=strongest.rule_name,
                sha256=fingerprint.sha256, path=fingerprint.path
            )

        reason = "No configured signature or heuristic matched this file."
        if is_script and fingerprint.size_bytes > SCRIPT_PREVIEW_BYTES: reason += f" Script pattern checks covered only the first {SCRIPT_PREVIEW_BYTES} bytes."
        return DetectionResult(
            status=DetectionStatus.NO_DETECTION, confidence=0.0,
            reason=reason, rule_name="no_rule_matched",
            sha256=fingerprint.sha256, path=fingerprint.path
        )