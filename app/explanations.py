from __future__ import annotations
from dataclasses import dataclass; from enum import Enum
from app.cleanup_verifier import CleanupVerificationResult, VerificationStatus; from app.incidents import IncidentDetails, IncidentEventType; from app.models import DetectionStatus, StoredScanResult; from app.quarantine import QuarantineItem, QuarantineState; from app.recovery import RecoveryAttempt, RecoveryStatus

SAFE_SCAN_WORDING = "No threats detected in the files successfully scanned."

class ExplanationSeverity(str, Enum): CLEAN = "CLEAN"; SUSPICIOUS = "SUSPICIOUS"; DANGEROUS = "DANGEROUS"; SCAN_ISSUE = "SCAN_ISSUE"

@dataclass(frozen=True)
class SecurityExplanation:
    path: str; severity: ExplanationSeverity; confidence: float | None; summary: str; evidence: tuple[str, ...]; actions: tuple[str, ...]; cautions: tuple[str, ...] = ()
    def to_dict(self) -> dict[str, object]: return {"path": self.path, "severity": self.severity.value, "confidence": self.confidence, "summary": self.summary, "evidence": list(self.evidence), "actions": list(self.actions), "cautions": list(self.cautions)}

@dataclass(frozen=True)
class ExplanationContext:
    result: StoredScanResult; incident: IncidentDetails | None = None; quarantine_items: tuple[QuarantineItem, ...] = (); latest_verification: CleanupVerificationResult | None = None; recovery_attempts: tuple[RecoveryAttempt, ...] = ()

def build_explanation(context: ExplanationContext) -> SecurityExplanation:
    result = context.result
    if result.detection_status is DetectionStatus.HIGH_CONFIDENCE: return _dangerous(context)
    if result.detection_status is DetectionStatus.LOW_CONFIDENCE: return _suspicious(context)
    if result.detection_status is DetectionStatus.NO_DETECTION: return SecurityExplanation(path=result.path, severity=ExplanationSeverity.CLEAN, confidence=result.detection_confidence, summary="No configured signature or heuristic identified this file as a threat during this scan.", evidence=(result.detection_reason or result.reason,), actions=("No automatic quarantine action was required for this scan result.",), cautions=("This statement applies only to the file evidence evaluated during this scan.",))
    return SecurityExplanation(path=result.path, severity=ExplanationSeverity.SCAN_ISSUE, confidence=None, summary="This file was not fully evaluated for threats.", evidence=(result.reason,), actions=("Review the scan issue and rescan the file when it is accessible and supported.",), cautions=("AutoGuard cannot make a threat conclusion for a file that was not successfully scanned.",))

def _dangerous(context: ExplanationContext) -> SecurityExplanation:
    result = context.result; evidence: list[str] = []; actions: list[str] = []; cautions: list[str] = []
    if result.sha256: evidence.append(f"SHA-256: {result.sha256}.")
    if result.matched_signature_name:
        kind = result.matched_signature_kind.value if result.matched_signature_kind else "signature"
        evidence.append(f"Exact known-signature evidence: {result.matched_signature_name} ({kind}).")
    if result.detection_reason: evidence.append(result.detection_reason)
    if result.rule_name: evidence.append(f"Detection rule: {result.rule_name}.")

    successful = tuple(item for item in context.quarantine_items if item.state is QuarantineState.QUARANTINED)
    failed = tuple(item for item in context.quarantine_items if item.state is QuarantineState.FAILED)
    direct_success = tuple(item for item in successful if item.original_path == result.path)

    if direct_success: actions.append(f"Quarantine succeeded for this detected location ({len(direct_success)} verified quarantine object(s)).")
    elif failed: actions.append(f"Quarantine did not fully succeed for all related attempts ({len(failed)} failed attempt(s)).")
    else: actions.append("No successful quarantine record is available for this detected location.")

    if context.incident is not None:
        events = context.incident.events; found = sum(event.event_type is IncidentEventType.MATCHING_COPY_FOUND for event in events); quarantined_matches = sum(event.event_type is IncidentEventType.MATCHING_COPY_QUARANTINED for event in events); already = sum(event.event_type is IncidentEventType.MATCHING_COPY_ALREADY_CONTAINED for event in events)
        evidence.append(f"Incident status: {context.incident.incident.status.value}; reappearance count: {context.incident.incident.reappearance_count}.")
        actions.append(f"Matching-Copy Cleanup evidence: {found} exact matching copy event(s) found, {quarantined_matches} quarantined, {already} already contained.")
        if context.incident.incident.reappearance_count: cautions.append("This threat has reappeared after cleanup. Another application, archive, synchronization process, removable drive, or other source may be recreating it.")

    verification = context.latest_verification
    if verification is not None:
        actions.append(f"Cleanup verification: {verification.status.value}; verified quarantine objects {verification.verified_quarantine_objects}/{verification.quarantined_copies}; remaining exact matches {verification.remaining_matching_copies}; inaccessible locations {verification.inaccessible_locations}; verification errors {verification.verification_errors}.")
        if verification.status is not VerificationStatus.VERIFIED: cautions.append("Cleanup could not be fully verified from the available evidence.")

    if successful:
        latest_recovery = context.recovery_attempts[-1] if context.recovery_attempts else None
        if latest_recovery is None: actions.append("Recovery is available as a user-requested action. Before restoration, AutoGuard re-verifies quarantine integrity and evaluates the file with the current detector/signatures.")
        else:
            actions.append(f"Latest recovery attempt status: {latest_recovery.status.value}.")
            if latest_recovery.status is RecoveryStatus.DANGEROUS_BLOCKED: cautions.append("The latest recovery attempt was blocked because current detection still considered the file dangerous.")
    else: actions.append("No verified quarantined object is currently available for recovery.")

    return SecurityExplanation(path=result.path, severity=ExplanationSeverity.DANGEROUS, confidence=result.detection_confidence, summary="AutoGuard recorded a high-confidence dangerous detection backed by exact signature evidence.", evidence=tuple(evidence), actions=tuple(actions), cautions=tuple(cautions))

def _suspicious(context: ExplanationContext) -> SecurityExplanation:
    result = context.result; evidence = [result.detection_reason or result.reason]
    if result.rule_name: evidence.append(f"Heuristic rule: {result.rule_name}.")
    if result.sha256: evidence.append(f"Observed SHA-256: {result.sha256}.")

    stronger_quarantine = any(item.state is QuarantineState.QUARANTINED for item in context.quarantine_items)
    quarantine_text = ("This scan result itself was lower-confidence and did not justify automatic quarantine; a quarantine record exists for related content because stronger evidence was recorded elsewhere." if stronger_quarantine else "Automatic quarantine was not performed from this suspicious result because heuristic evidence is lower-confidence and is not sufficient by itself.")

    return SecurityExplanation(path=result.path, severity=ExplanationSeverity.SUSPICIOUS, confidence=result.detection_confidence, summary="AutoGuard found lower-confidence suspicious evidence, not a confirmed malicious signature match.", evidence=tuple(evidence), actions=(quarantine_text, "Review the file and context; rescan if stronger evidence becomes available."), cautions=("The file is not proven malicious by this lower-confidence evidence.",))