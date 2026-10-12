"""Hash-signature and heuristic file detection."""
from pathlib import Path
from typing import Iterable

from app.detection_rules import (
    DEFAULT_RULES,
    SCRIPT_EXTENSIONS,
    DetectionRule,
    RuleContext,
    decode_script_preview,
)
from app.hashing import inspect_file
from app.models import DetectionResult, DetectionStatus, FileInspection, SignatureKind
from app.signatures import SignatureStore

SCRIPT_PREVIEW_BYTES = 64 * 1024


class Detector:
    def __init__(
        self,
        signatures: SignatureStore,
        rules: Iterable[DetectionRule] = DEFAULT_RULES,
    ) -> None:
        self.signatures = signatures
        self.rules = tuple(rules)

    def detect_file(self, path: str | Path) -> DetectionResult:
        file_path = Path(path)
        preview_bytes = SCRIPT_PREVIEW_BYTES if file_path.suffix.lower() in SCRIPT_EXTENSIONS else 0
        return self.detect_inspection(inspect_file(file_path, preview_bytes=preview_bytes))

    def detect_inspection(self, inspection: FileInspection) -> DetectionResult:
        fingerprint = inspection.fingerprint
        file_path = Path(fingerprint.path)
        is_script = file_path.suffix.lower() in SCRIPT_EXTENSIONS

        signature = self.signatures.lookup(fingerprint.sha256)
        if signature is not None:
            is_test = signature.kind is SignatureKind.AUTOGUARD_TEST
            if is_test:
                reason = (
                    f"Exact match to configured AutoGuard test signature "
                    f"'{signature.name}'. This is a harmless simulated test detection, "
                    "not evidence that this file is real malware."
                )
                rule_name = "autoguard_test_signature"
            else:
                reason = f"SHA-256 matches known malicious signature: {signature.name}."
                rule_name = "known_malicious_sha256"

            return DetectionResult(
                status=DetectionStatus.HIGH_CONFIDENCE,
                confidence=1.0,
                reason=reason,
                rule_name=rule_name,
                sha256=fingerprint.sha256,
                path=fingerprint.path,
                matched_signature=signature,
            )

        context = RuleContext(
            file_path,
            decode_script_preview(inspection.preview),
        )
        matches = [
            match
            for rule in self.rules
            if (match := rule(context)) is not None
        ]
        if matches:
            strongest = max(matches, key=lambda match: match.confidence)
            return DetectionResult(
                status=DetectionStatus.LOW_CONFIDENCE,
                confidence=strongest.confidence,
                reason=strongest.reason,
                rule_name=strongest.rule_name,
                sha256=fingerprint.sha256,
                path=fingerprint.path,
            )

        reason = "No configured signature or heuristic matched this file."
        if is_script and fingerprint.size_bytes > SCRIPT_PREVIEW_BYTES:
            reason += (
                f" Script pattern checks covered only the first "
                f"{SCRIPT_PREVIEW_BYTES} bytes."
            )

        return DetectionResult(
            status=DetectionStatus.NO_DETECTION,
            confidence=0.0,
            reason=reason,
            rule_name="no_rule_matched",
            sha256=fingerprint.sha256,
            path=fingerprint.path,
        )
