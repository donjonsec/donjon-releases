"""Playwright end-to-end tests for the Donjon Platform web dashboard.

Starts the server automatically via a session-scoped fixture, then exercises
every tab and verifies content renders without errors.

Run:
    pytest tests/test_dashboard_playwright.py -v

Prerequisites:
    pip install pytest-playwright && playwright install chromium
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8443
BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"

# All 10 sidebar tabs: (data-tab id, expected heading text)
SIDEBAR_TABS = [
    ("overview", "Overview"),
    ("scan-center", "Scan Center"),
    ("compliance", "Compliance"),
    ("risk-analysis", "Risk Analysis"),
    ("patch-verification", "Patch Verification"),
    ("schedules", "Schedules"),
    ("ai-assistant", "AI Assistant"),
    ("trends", "Trends"),
    ("lifecycle", "License"),
    ("settings", "Settings"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def server():
    """Start the Donjon server if it is not already running.

    Sets DONJON_ACCEPT_EULA=yes and DONJON_ALLOW_NO_AUTH=1 so the server
    boots without interactive prompts and without API-key auth.
    """
    if _port_open(SERVER_HOST, SERVER_PORT):
        # Server is already running externally — reuse it.
        yield BASE_URL
        return

    env = os.environ.copy()
    env["DONJON_ACCEPT_EULA"] = "yes"
    env["DONJON_ALLOW_NO_AUTH"] = "1"

    proc = subprocess.Popen(
        [
            sys.executable,
            str(PROJECT_ROOT / "bin" / "start-server.py"),
            "--host", SERVER_HOST,
            "--port", str(SERVER_PORT),
            "--no-auth",
        ],
        env=env,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # Wait for server to accept connections (up to 30 s).
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if _port_open(SERVER_HOST, SERVER_PORT):
            break
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            pytest.fail(f"Server exited early (rc={proc.returncode}):\n{out}")
        time.sleep(0.5)
    else:
        proc.terminate()
        pytest.fail("Server did not start within 30 seconds")

    yield BASE_URL

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture()
def dashboard(server: str, page: Page):
    """Navigate to the dashboard and wait for it to settle.

    Collects console errors so individual tests can inspect them.
    """
    errors: list[str] = []
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)

    page.goto(server, wait_until="domcontentloaded")
    # Wait for the sidebar to render — proves the shell loaded.
    page.locator(".nav-item").first.wait_for(state="visible", timeout=10000)
    # Brief pause for initial API fetches to settle.
    page.wait_for_timeout(1500)

    # Attach error list so tests can inspect it.
    page._console_errors = errors  # type: ignore[attr-defined]
    return page


def _click_tab(page: Page, tab_id: str) -> None:
    """Click a sidebar tab and wait for the content pane to become active."""
    nav = page.locator(f'.nav-item[data-tab="{tab_id}"]')
    nav.click()
    page.locator(f'#tab-{tab_id}.active').wait_for(state="visible", timeout=5000)
    # Brief pause for async content fetches triggered by tabload event.
    page.wait_for_timeout(800)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestDashboardBasics:
    """Fundamental page-load checks."""

    def test_page_title(self, dashboard: Page):
        """#1 - Page loads with title 'Donjon Platform'."""
        expect(dashboard).to_have_title("Donjon Platform")

    def test_sidebar_tabs_present(self, dashboard: Page):
        """#2 - All 10 sidebar tabs are present."""
        for tab_id, label in SIDEBAR_TABS:
            nav = dashboard.locator(f'.nav-item[data-tab="{tab_id}"]')
            expect(nav).to_be_visible()
            expect(nav).to_contain_text(label)

    def test_dashboard_size(self, dashboard: Page):
        """#11 - Dashboard HTML is > 20 KB (not empty/broken)."""
        html = dashboard.content()
        assert len(html) > 20_000, f"Dashboard HTML too small: {len(html)} bytes"

    def test_favicon_loads(self, server: str, page: Page):
        """#9 - Favicon loads without 404."""
        resp = page.request.get(f"{server}/favicon.ico")
        assert resp.status == 200, f"Favicon returned {resp.status}"

    def test_footer_version(self, dashboard: Page):
        """#8 - Footer shows 'v7.3' (not 'v2.0')."""
        footer = dashboard.locator(".sidebar-footer")
        expect(footer).to_contain_text("v7.3")
        assert "v2.0" not in (footer.text_content() or "")


class TestTabNavigation:
    """#3 - Click each tab, verify heading changes and content loads."""

    @pytest.mark.parametrize("tab_id,label", SIDEBAR_TABS, ids=[t[0] for t in SIDEBAR_TABS])
    def test_tab_switches_and_loads(self, dashboard: Page, tab_id: str, label: str):
        _click_tab(dashboard, tab_id)

        # Heading updates to match the tab label.
        # Note: headings include Unicode icon prefixes (e.g., "⌂Overview")
        title_el = dashboard.locator("#pageTitle")
        title_text = title_el.inner_text()
        assert label.lower() in title_text.lower(), f"Expected '{label}' in heading, got '{title_text}'"

        # Content pane is active and not stuck on "Loading...".
        pane = dashboard.locator(f"#tab-{tab_id}.active")
        expect(pane).to_be_visible()
        # Allow a moment for async content, then verify no "Loading..." text.
        dashboard.wait_for_timeout(500)
        pane_text = pane.text_content() or ""
        assert "Loading\u2026" not in pane_text, (
            f"Tab '{tab_id}' still shows 'Loading\u2026' after navigation"
        )


class TestOverviewTab:
    """#4 - Overview tab shows stat cards and module status badges."""

    def test_stat_cards_present(self, dashboard: Page):
        _click_tab(dashboard, "overview")
        cards = dashboard.locator("#ovCards .ov-card")
        expect(cards.first).to_be_visible()
        count = cards.count()
        assert count >= 4, f"Expected at least 4 stat cards, got {count}"

    def test_module_status_section(self, dashboard: Page):
        _click_tab(dashboard, "overview")
        # Wait for module badges to render (populated via /api/v1/health).
        dashboard.wait_for_timeout(1000)
        modules = dashboard.locator("#ovModules span")
        count = modules.count()
        assert count >= 1, "No module status badges rendered"


class TestScanCenter:
    """#5 - Scan Center shows 17 scanner cards."""

    def test_scanner_cards(self, dashboard: Page):
        _click_tab(dashboard, "scan-center")
        # Scanner cards are generated dynamically from /api/v1/scanners.
        dashboard.wait_for_timeout(1500)
        cards = dashboard.locator(".sc-card")
        count = cards.count()
        assert count == 17, f"Expected 17 scanner cards, got {count}"


class TestTrendsTab:
    """#6 - Trends tab renders SVG charts."""

    def test_svg_charts_rendered(self, dashboard: Page):
        _click_tab(dashboard, "trends")
        # Charts are drawn via JS after tabload event — give them time.
        dashboard.wait_for_timeout(2000)

        # There should be SVG elements inside the chart containers.
        for chart_id in ("trComplianceChart", "trVelocityChart", "trSeverityChart"):
            container = dashboard.locator(f"#{chart_id}")
            expect(container).to_be_visible()
            svgs = container.locator("svg")
            assert svgs.count() >= 1, f"No SVG in #{chart_id}"


class TestLicenseTab:
    """#7 - License tab shows feature matrix with 17 rows."""

    def test_feature_matrix_rows(self, dashboard: Page):
        _click_tab(dashboard, "lifecycle")
        dashboard.wait_for_timeout(1000)
        rows = dashboard.locator("#lcFeatureBody tr")
        count = rows.count()
        assert count == 17, f"Expected 17 feature rows, got {count}"


class TestConsoleErrors:
    """#10 - No JavaScript console errors on any tab."""

    def test_no_console_errors(self, dashboard: Page):
        errors: list[str] = []
        # Clear any errors from initial load — we re-collect from scratch.
        dashboard._console_errors.clear()  # type: ignore[attr-defined]

        # Navigate every tab.
        for tab_id, _label in SIDEBAR_TABS:
            _click_tab(dashboard, tab_id)
            dashboard.wait_for_timeout(300)

        errors = dashboard._console_errors  # type: ignore[attr-defined]
        # Filter out known non-actionable noise (e.g., favicon 404 in some envs).
        real_errors = [e for e in errors if "favicon" not in e.lower()]
        assert real_errors == [], f"Console errors found:\n" + "\n".join(real_errors)


class TestThemeToggle:
    """#12 - Dark/light theme toggle works."""

    def test_theme_toggle(self, dashboard: Page):
        html_el = dashboard.locator("html")

        # Default theme is dark.
        expect(html_el).to_have_attribute("data-theme", "dark")

        # Click toggle — should switch to light.
        dashboard.locator("#themeToggle").click()
        expect(html_el).to_have_attribute("data-theme", "light")

        # Click again — back to dark.
        dashboard.locator("#themeToggle").click()
        expect(html_el).to_have_attribute("data-theme", "dark")
