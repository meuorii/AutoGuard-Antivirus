from pathlib import Path

from app.models import DetectionResult, DetectionStatus, ScanResult, ScanStatus, Signature, SignatureKind
from app.windows_notifications import FileVerdictNotifier


class FakeBackend:
    def __init__(self):
        self.items = []

    def show(self, title: str, message: str) -> None:
        self.items.append((title, message))


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


def detection(path: Path, status: DetectionStatus) -> DetectionResult:
    sha = "a" * 64
    if status is DetectionStatus.HIGH_CONFIDENCE:
        signature = Signature("Test threat", sha, SignatureKind.AUTOGUARD_TEST)
        return DetectionResult(status, 1.0, "Exact signature match.", "sha256_signature", sha, str(path), signature)
    if status is DetectionStatus.LOW_CONFIDENCE:
        return DetectionResult(status, 0.5, "Suspicious evidence.", "heuristic", sha, str(path))
    return DetectionResult(status, 0.0, "No threat detected.", "none", sha, str(path))


def test_clean_notification_is_limited_to_new_downloads(tmp_path):
    downloads = tmp_path / "Downloads"; downloads.mkdir()
    desktop = tmp_path / "Desktop"; desktop.mkdir()
    backend = FakeBackend()
    notifier = FileVerdictNotifier((downloads,), backend=backend)

    downloaded = downloads / "installer.exe"
    clean = ScanResult(str(downloaded), ScanStatus.SCANNED, "No threat", detection=detection(downloaded, DetectionStatus.NO_DETECTION))
    assert notifier.handle_scan_result(clean, "created")
    assert backend.items[-1][0] == "installer.exe checked"
    assert "No threats detected" in backend.items[-1][1]

    edited = desktop / "notes.txt"
    edited_result = ScanResult(str(edited), ScanStatus.SCANNED, "No threat", detection=detection(edited, DetectionStatus.NO_DETECTION))
    assert not notifier.handle_scan_result(edited_result, "created")
    assert not notifier.handle_scan_result(clean, "modified")


def test_suspicious_and_confirmed_threats_notify_from_any_monitored_location(tmp_path):
    downloads = tmp_path / "Downloads"; downloads.mkdir()
    desktop = tmp_path / "Desktop"; desktop.mkdir()
    backend = FakeBackend()
    notifier = FileVerdictNotifier((downloads,), backend=backend)

    suspicious_path = desktop / "odd.js"
    suspicious = ScanResult(str(suspicious_path), ScanStatus.SCANNED, "Suspicious", detection=detection(suspicious_path, DetectionStatus.LOW_CONFIDENCE))
    assert notifier.handle_scan_result(suspicious, "created")
    assert backend.items[-1][0] == "Suspicious file found"
    # Repeated ordinary edits to a low-confidence file stay in Activity.
    assert not notifier.handle_scan_result(suspicious, "modified")

    confirmed_path = desktop / "bad.exe"
    confirmed = ScanResult(str(confirmed_path), ScanStatus.SCANNED, "Threat", detection=detection(confirmed_path, DetectionStatus.HIGH_CONFIDENCE))
    assert notifier.handle_scan_result(confirmed, "modified")
    assert backend.items[-1][0] == "Confirmed threat detected"


def test_browser_temporary_download_does_not_emit_clean_verdict(tmp_path):
    downloads = tmp_path / "Downloads"; downloads.mkdir()
    backend = FakeBackend()
    notifier = FileVerdictNotifier((downloads,), backend=backend)
    temp = downloads / "setup.exe.crdownload"
    result = ScanResult(str(temp), ScanStatus.SCANNED, "No threat", detection=detection(temp, DetectionStatus.NO_DETECTION))
    assert not notifier.handle_scan_result(result, "created")
    assert backend.items == []


def test_download_incomplete_scan_warns_and_duplicate_verdict_is_cooled_down(tmp_path):
    downloads = tmp_path / "Downloads"; downloads.mkdir()
    backend = FakeBackend(); clock = FakeClock()
    notifier = FileVerdictNotifier((downloads,), backend=backend, cooldown_seconds=60.0, clock=clock)
    path = downloads / "large.iso"
    result = ScanResult(str(path), ScanStatus.SKIPPED_SIZE, "Too large")

    assert notifier.handle_scan_result(result, "moved")
    assert backend.items[-1][0] == "Could not fully check large.iso"
    assert not notifier.handle_scan_result(result, "moved")
    clock.value += 61
    assert notifier.handle_scan_result(result, "moved")
    health = notifier.health()
    assert health.notifications_sent == 2
    assert health.notifications_suppressed == 1