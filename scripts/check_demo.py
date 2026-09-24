"""Smoke-test the live Pages demo in headless Chromium and save screenshots.

    uv run --with playwright playwright install chromium   # once
    uv run --with playwright python scripts/check_demo.py [URL]

Fails (exit 1) on console errors, failed requests, an empty chart/table, or a status message.
"""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

URL = sys.argv[1] if len(sys.argv) > 1 else "https://reeve25.github.io/vulnprio/"
OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
VIEWPORTS = {"desktop": (1440, 900), "phone": (390, 844)}


def check(browser, name, width, height):
    errors = []
    page = browser.new_page(viewport={"width": width, "height": height}, device_scale_factor=2)
    page.on("console", lambda m: m.type == "error" and errors.append(f"console: {m.text}"))
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    page.on("requestfailed", lambda r: errors.append(f"requestfailed: {r.url}"))
    page.on("response", lambda r: r.status >= 400 and errors.append(f"HTTP {r.status}: {r.url}"))
    page.goto(URL, wait_until="networkidle")
    page.wait_for_selector("#rows tr", timeout=15_000)

    stats = page.evaluate(
        """() => ({
          rows: document.querySelectorAll('#rows tr').length,
          dots: document.querySelectorAll('#scatter circle').length,
          total: document.getElementById('t-total').textContent,
          act: document.getElementById('t-act').textContent,
          headline: document.getElementById('headline').textContent,
          status: document.getElementById('status').textContent,
          scans: document.querySelectorAll('#scan option').length,
          foot: document.getElementById('foot').textContent,
          hscroll: document.documentElement.scrollWidth > document.documentElement.clientWidth,
        })"""
    )
    problems = list(errors)
    if stats["rows"] == 0 or stats["dots"] == 0 or stats["scans"] == 0:
        problems.append(f"empty render: {stats}")
    if stats["total"] in ("–", "0") or stats["status"]:
        problems.append(f"no data / status shown: {stats}")
    if stats["hscroll"]:
        problems.append("page scrolls horizontally")

    OUT.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=OUT / f"{name}.png")  # first screen: headline, tiles, chart
    for i, part in enumerate(("chart", "table")):
        page.locator(".card").nth(i).evaluate("e => e.scrollIntoView()")
        page.screenshot(path=OUT / f"{name}-{part}.png")
    page.close()
    print(
        f"{name} {width}x{height}: {stats['scans']} scans, {stats['dots']} dots, {stats['rows']} rows, "
        f"total={stats['total']} act_now={stats['act']} hscroll={stats['hscroll']}"
    )
    print(f"  {stats['headline']}\n  {stats['foot']}")
    return problems


with sync_playwright() as p:
    browser = p.chromium.launch()
    problems = [f"{n}: {x}" for n, (w, h) in VIEWPORTS.items() for x in check(browser, n, w, h)]
    browser.close()

for x in problems:
    print("FAIL", x)
sys.exit(1 if problems else 0)
