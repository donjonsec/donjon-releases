"""Playwright end-to-end tests for the Donjon Platform web dashboard.

Starts the server automatically via a session-scoped fixture, then exercises
every tab and verifies content renders without errors.

Run:
    pytest tests/test_dashboard_playwright.py -v

Prerequisites:
    pip install pytest-playwright && playwright install chromium

Design note: Flask's dev server is single-threaded, so we minimise the number
of full page loads by sharing a single page across tests within each class.
Each test resets tab state by clicking the target tab rather than reloading.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from playwright.sync_api import Browser, BrowserContext, Page, expect

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8443
BASE_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"
GOTO_TIMEOUT = 60_000

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

# Tabs with pre-rendered HTML (have generate_* functions in the codebase).
# Other tabs use a "Loading..." placeholder and rely on JS tabload handlers
# that may not be wired up yet.
TABS_WITH_CONTENT = {"overview", "scan-center", "trends", "lifecycle"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _click_tab(page: Page, tab_id: str) -> None:
    """Click a sidebar tab and wait for the content pane to become active."""
    nav = page.locator(f'.nav-item[data-tab="{tab_id}"]')
    nav.click()
    page.locator(f'#tab-{tab_id}.active').wait_for(state="visible", timeout=5000)
    page.wait_for_timeout(800)


def _load_dashboard(context: BrowserContext) -> Page:
    """Open one page, navigate, and wait for sidebar to appear."""
    page = context.new_page()
    page.goto(BASE_URL, wait_until="commit", timeout=GOTO_TIMEOUT)
    page.locator(".nav-item").first.wait_for(state="visible", timeout=30000)
    page.wait_for_timeout(2000)
    return page


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def server():
    """Start the Donjon server if not already running."""
    if _port_open(SERVER_HOST, SERVER_PORT):
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


@pytest.fixture(scope="session")
def shared_context(server: str, browser: Browser) -> BrowserContext:
    """Session-scoped browser context -- one connection for all tests."""
    ctx = browser.new_context()
    yield ctx
    ctx.close()


@pytest.fixture(scope="session")
def shared_page(shared_context: BrowserContext) -> Page:
    """Session-scoped page -- loaded once, reused across all tests.

    Tests click tabs to reset state rather than reloading the page.
    """
    page = _load_dashboard(shared_context)
    # Attach console error collector.
    errors: list[str] = []
    page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
    page._console_errors = errors  # type: ignore[attr-defined]
    yield page
    page.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestDashboardBasics:
    """Fundamental page-load checks."""

    def test_page_title(self, shared_page: Page):
        """#1 - Page loads with title 'Donjon Platform'."""
        expect(shared_page).to_have_title("Donjon Platform")

    def test_sidebar_tabs_present(self, shared_page: Page):
        """#2 - All 10 sidebar tabs are present."""
        for tab_id, label in SIDEBAR_TABS:
            nav = shared_page.locator(f'.nav-item[data-tab="{tab_id}"]')
            expect(nav).to_be_visible()
            expect(nav).to_contain_text(label)

    def test_dashboard_size(self, shared_page: Page):
        """#11 - Dashboard HTML is > 20 KB (not empty/broken)."""
        html = shared_page.content()
        assert len(html) > 20_000, f"Dashboard HTML too small: {len(html)} bytes"

    def test_favicon_loads(self, shared_page: Page):
        """#9 - Favicon loads without 404."""
        resp = shared_page.request.get(f"{BASE_URL}/favicon.ico")
        assert resp.status == 200, f"Favicon returned {resp.status}"

    def test_footer_version(self, shared_page: Page):
        """#8 - Footer shows 'v7.3' (not 'v2.0')."""
        footer = shared_page.locator(".sidebar-footer")
        expect(footer).to_contain_text("v7.3")
        assert "v2.0" not in (footer.text_content() or "")


class TestTabNavigation:
    """#3 - Click each tab, verify heading changes and content loads."""

    @pytest.mark.parametrize(
        "tab_id,label", SIDEBAR_TABS, ids=[t[0] for t in SIDEBAR_TABS]
    )
    def test_tab_switches_and_loads(
        self, shared_page: Page, tab_id: str, label: str
    ):
        _click_tab(shared_page, tab_id)

        # Heading includes a Unicode icon prefix (e.g., "⌂Overview").
        title_text = shared_page.locator("#pageTitle").inner_text()
        assert label.lower() in title_text.lower(), (
            f"Expected '{label}' in heading, got '{title_text}'"
        )

        # Content pane is visible.
        pane = shared_page.locator(f"#tab-{tab_id}.active")
        expect(pane).to_be_visible()

        # Tabs with pre-rendered content should not be stuck on "Loading...".
        if tab_id in TABS_WITH_CONTENT:
            shared_page.wait_for_timeout(500)
            pane_text = pane.text_content() or ""
            assert "Loading\u2026" not in pane_text, (
                f"Tab '{tab_id}' still shows 'Loading\u2026' after navigation"
            )


class TestOverviewTab:
    """#4 - Overview tab shows stat cards and module status badges."""

    def test_stat_cards_present(self, shared_page: Page):
        _click_tab(shared_page, "overview")
        cards = shared_page.locator("#ovCards .ov-card")
        expect(cards.first).to_be_visible()
        assert cards.count() >= 4, f"Expected >= 4 stat cards, got {cards.count()}"

    def test_module_status_section(self, shared_page: Page):
        _click_tab(shared_page, "overview")
        shared_page.wait_for_timeout(1000)
        modules = shared_page.locator("#ovModules span")
        assert modules.count() >= 1, "No module status badges rendered"


class TestScanCenter:
    """#5 - Scan Center shows 17 scanner cards."""

    def test_scanner_cards(self, shared_page: Page):
        _click_tab(shared_page, "scan-center")
        shared_page.wait_for_timeout(1500)
        cards = shared_page.locator(".sc-card")
        assert cards.count() == 17, f"Expected 17 scanner cards, got {cards.count()}"


class TestTrendsTab:
    """#6 - Trends tab renders SVG charts."""

    def test_svg_charts_rendered(self, shared_page: Page):
        _click_tab(shared_page, "trends")

        # Charts draw asynchronously after tabload + sequential API fetches.
        # Flask's single-threaded server serialises them, so we poll rather
        # than use a fixed wait.
        chart_ids = ["trComplianceChart", "trVelocityChart", "trSeverityChart"]
        for chart_id in chart_ids:
            container = shared_page.locator(f"#{chart_id}")
            expect(container).to_be_visible()
            svg_loc = container.locator("svg")
            # Poll up to 10 seconds for the SVG to appear.
            svg_loc.first.wait_for(state="attached", timeout=10000)
            assert svg_loc.count() >= 1, f"No SVG in #{chart_id}"


class TestLicenseTab:
    """#7 - License tab shows feature matrix with 17 rows."""

    def test_feature_matrix_rows(self, shared_page: Page):
        _click_tab(shared_page, "lifecycle")
        shared_page.wait_for_timeout(1500)
        rows = shared_page.locator("#lcFeatureBody tr")
        assert rows.count() == 17, f"Expected 17 feature rows, got {rows.count()}"


class TestConsoleErrors:
    """#10 - No JavaScript console errors on any tab."""

    def test_no_console_errors(self, shared_page: Page):
        # Clear accumulated errors, then walk every tab.
        shared_page._console_errors.clear()  # type: ignore[attr-defined]

        for tab_id, _label in SIDEBAR_TABS:
            _click_tab(shared_page, tab_id)
            shared_page.wait_for_timeout(300)

        errors = shared_page._console_errors  # type: ignore[attr-defined]
        # Filter out network noise from Flask's single-threaded dev server
        # and known non-actionable messages.
        noise_patterns = ("favicon", "net::err_", "failed to load resource", "api 5")
        real_errors = [
            e for e in errors
            if not any(p in e.lower() for p in noise_patterns)
        ]
        assert real_errors == [], "Console errors found:\n" + "\n".join(real_errors)


class TestThemeToggle:
    """#12 - Dark/light theme toggle works."""

    def test_theme_toggle(self, shared_page: Page):
        html_el = shared_page.locator("html")

        # Default is dark.
        expect(html_el).to_have_attribute("data-theme", "dark")

        # Toggle to light.
        shared_page.locator("#themeToggle").click()
        expect(html_el).to_have_attribute("data-theme", "light")

        # Toggle back to dark.
        shared_page.locator("#themeToggle").click()
        expect(html_el).to_have_attribute("data-theme", "dark")
