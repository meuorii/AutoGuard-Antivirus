from pathlib import Path

from app.logging_config import application_logger, configure_production_logging, monitor_logger, scanner_logger, shutdown_production_logging
from app.signatures import AUTOGUARD_TEST_SHA256, load_signatures


def test_production_logging_creates_separate_rotating_logs(tmp_path):
    paths = configure_production_logging(tmp_path / "logs")
    application_logger().info("application ready"); scanner_logger().warning("scanner evidence"); monitor_logger().error("monitor failure")
    shutdown_production_logging()
    assert set(paths) == {"application", "scanner", "monitor", "error"}
    assert "application ready" in paths["application"].read_text(encoding="utf-8")
    assert "scanner evidence" in paths["scanner"].read_text(encoding="utf-8")
    assert "monitor failure" in paths["monitor"].read_text(encoding="utf-8")
    assert "monitor failure" in paths["error"].read_text(encoding="utf-8")


def test_packaging_configuration_bundles_signatures_and_keeps_runtime_data_external():
    root = Path(__file__).resolve().parents[1]; spec = (root / "AutoGuard.spec").read_text(encoding="utf-8"); config = (root / "app/config.py").read_text(encoding="utf-8")
    assert "data/signatures.json" in spec.replace("\\\\", "/") or "signatures.json" in spec
    assert "customtkinter" in spec and "collect_data_files" in spec
    assert "Path.home() / \"AutoGuardData\"" in config
    store = load_signatures(); assert store.lookup(AUTOGUARD_TEST_SHA256) is not None


def test_windows_notification_dependency_is_packaged():
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "requirements.txt").read_text(encoding="utf-8")
    spec = (root / "AutoGuard.spec").read_text(encoding="utf-8")
    assert "winotify" in requirements
    assert 'collect_submodules("winotify")' in spec


def test_system_tray_dependencies_are_packaged():
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "requirements.txt").read_text(encoding="utf-8")
    spec = (root / "AutoGuard.spec").read_text(encoding="utf-8")
    assert "pystray" in requirements
    assert "Pillow" in requirements
    assert 'collect_submodules("pystray")' in spec
    assert 'collect_submodules("PIL")' in spec


def test_official_logo_assets_are_packaged_and_reused_by_shell():
    root = Path(__file__).resolve().parents[1]
    spec = (root / "AutoGuard.spec").read_text(encoding="utf-8")
    sidebar = (root / "app/ui/sidebar.py").read_text(encoding="utf-8")
    tray = (root / "app/system_tray.py").read_text(encoding="utf-8")
    assert (root / "assets/autoguard_logo.png").is_file()
    assert (root / "assets/autoguard.ico").is_file()
    assert 'assets_dir = project_root / "assets"' in spec
    assert 'icon=str(project_root / "assets" / "autoguard.ico")' in spec
    assert "autoguard_logo_path" in sidebar
    assert "autoguard_logo_path" in tray


def test_resource_helper_supports_pyinstaller_meipass(monkeypatch, tmp_path):
    import sys
    from app.resources import autoguard_logo_path, resource_root
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert resource_root() == tmp_path
    assert autoguard_logo_path() == tmp_path / "assets" / "autoguard_logo.png"


def test_windows_shell_uses_ico_and_explicit_app_identity():
    root = Path(__file__).resolve().parents[1]
    resources = (root / "app/resources.py").read_text(encoding="utf-8")
    window = (root / "app/ui/main_window.py").read_text(encoding="utf-8")
    main = (root / "main.py").read_text(encoding="utf-8")
    assert "SetCurrentProcessExplicitAppUserModelID" in resources
    assert "WINDOWS_APP_USER_MODEL_ID" in resources
    assert "autoguard_icon_path" in window
    assert "iconbitmap(default=str(icon_path))" in window
    assert "self.after(500, self._apply_window_icon)" in window
    assert "configure_windows_app_identity()" in main
    assert '"--start-hidden"' in main
    assert "start_hidden=args.start_hidden" in main


def test_windows_app_identity_is_safe_noop_off_windows():
    from app.resources import configure_windows_app_identity
    assert configure_windows_app_identity(platform_name="posix") is False


def test_release_exe_has_windows_version_metadata():
    root = Path(__file__).resolve().parents[1]
    spec = (root / "AutoGuard.spec").read_text(encoding="utf-8")
    version = (root / "version_info.txt").read_text(encoding="utf-8")
    assert 'version=str(project_root / "version_info.txt")' in spec
    assert "AutoGuard Automatic Antivirus" in version
    assert "ProductVersion', '1.0.0'" in version
    assert "OriginalFilename', 'AutoGuard.exe'" in version


def test_release_installer_uses_existing_app_identity_and_keeps_runtime_data():
    root = Path(__file__).resolve().parents[1]
    installer = (root / "installer/AutoGuard.iss").read_text(encoding="utf-8")
    resources = (root / "app/resources.py").read_text(encoding="utf-8")
    assert 'MyAppUserModelId "AutoGuard.Desktop"' in installer
    assert 'WINDOWS_APP_USER_MODEL_ID = "AutoGuard.Desktop"' in resources
    assert "DefaultDirName={localappdata}\\Programs\\{#MyAppName}" in installer
    assert "Keep security history" in installer
    assert "SetupIconFile=..\\assets\\autoguard.ico" in installer


def test_release_build_script_runs_tests_before_pyinstaller():
    root = Path(__file__).resolve().parents[1]
    script = (root / "build_release.ps1").read_text(encoding="utf-8")
    assert "-m pytest -q" in script
    assert "-m PyInstaller --clean --noconfirm AutoGuard.spec" in script
    assert script.index("-m pytest -q") < script.index("-m PyInstaller --clean --noconfirm AutoGuard.spec")
    assert "AutoGuard-Setup-1.0.0.exe" in script


def test_release_installer_has_license_acceptance_and_normal_wizard_flow():
    root = Path(__file__).resolve().parents[1]
    installer = (root / "installer/AutoGuard.iss").read_text(encoding="utf-8")
    license_text = (root / "LICENSE.txt").read_text(encoding="utf-8")
    assert "LicenseFile=..\\LICENSE.txt" in installer
    assert "DisableWelcomePage=no" in installer
    assert "DisableDirPage=no" in installer
    assert "DisableReadyPage=no" in installer
    assert 'Name: "desktopicon"' in installer
    assert 'Description: "Launch {#MyAppName}"' in installer
    assert "AutoGuard Software License Agreement" in license_text
    assert "No security product can guarantee" in license_text


def test_release_build_script_requires_license_before_installer_compile():
    root = Path(__file__).resolve().parents[1]
    script = (root / "build_release.ps1").read_text(encoding="utf-8")
    assert 'Join-Path $root "LICENSE.txt"' in script
    assert 'Required installer license file is missing' in script
    assert script.index('Join-Path $root "LICENSE.txt"') < script.index(r'installer\AutoGuard.iss')


def test_installer_matches_autoguard_dark_theme_and_branding_assets():
    root = Path(__file__).resolve().parents[1]
    installer = (root / "installer/AutoGuard.iss").read_text(encoding="utf-8")
    assert "WizardStyle=modern dark includetitlebar hidebevels" in installer
    assert "WizardBackColor=#0C1012" in installer
    assert "autoguard_installer_gradient.png" in installer
    assert "autoguard_wizard.png" in installer
    assert "autoguard_wizard_small.png" in installer
    assert "WizardForm.Font.Name := 'Segoe UI'" in installer
    assert "WizardForm.WelcomeLabel1.Caption := 'Welcome to AutoGuard'" in installer
    assert "WizardForm.FinishedHeadingLabel.Caption := 'AutoGuard is ready'" in installer
    assert (root / "assets/installer/autoguard_installer_gradient.png").is_file()
    assert (root / "assets/installer/autoguard_wizard.png").is_file()
    assert (root / "assets/installer/autoguard_wizard_small.png").is_file()


def test_themed_installer_build_requires_supported_inno_setup_version():
    root = Path(__file__).resolve().parents[1]
    script = (root / "build_release.ps1").read_text(encoding="utf-8")
    assert 'Inno Setup 7\\ISCC.exe' in script
    assert 'Inno Setup 6\\ISCC.exe' in script
    assert '$minimumInnoVersion = [version]"6.7.0"' in script
    assert "themed installer requires Inno Setup 6.7.0 or newer" in script


def test_release_installer_offers_windows_startup_and_uses_hidden_start():
    root = Path(__file__).resolve().parents[1]
    installer = (root / "installer/AutoGuard.iss").read_text(encoding="utf-8")
    assert 'Name: "startup"' in installer
    assert 'Description: "Start AutoGuard with Windows"' in installer
    assert 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' in installer
    assert 'ValueName: "AutoGuard"' in installer
    assert '--start-hidden' in installer
    assert 'CurUninstallStepChanged' in installer
    assert 'RegDeleteValue' in installer


def test_release_version_remains_1_0_0_before_initial_release():
    root = Path(__file__).resolve().parents[1]
    installer = (root / "installer/AutoGuard.iss").read_text(encoding="utf-8")
    script = (root / "build_release.ps1").read_text(encoding="utf-8")
    assert '#define MyAppVersion "1.0.0"' in installer
    assert "AutoGuard-Setup-1.0.0.exe" in script