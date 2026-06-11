"""Convert SVG screenshots and HTML report to PNG using Playwright/Chromium."""
import os
import glob
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE = Path(__file__).parent
OUT  = BASE / "demo_screenshots"

def screenshot_svg(page, svg_path: Path) -> Path:
    png_path = svg_path.with_suffix(".png")
    page.set_viewport_size({"width": 1200, "height": 900})
    page.goto(svg_path.as_uri())
    page.wait_for_timeout(300)
    # Fit to SVG natural size
    dim = page.evaluate("""() => {
        const svg = document.querySelector('svg');
        if (!svg) return {w: 1200, h: 900};
        const r = svg.getBoundingClientRect();
        return {w: Math.ceil(r.width) + 40, h: Math.ceil(r.height) + 40};
    }""")
    page.set_viewport_size({"width": dim["w"], "height": dim["h"]})
    page.screenshot(path=str(png_path), full_page=False)
    return png_path


def screenshot_html(page, html_path: Path) -> Path:
    png_path = OUT / "05_html_report.png"
    page.set_viewport_size({"width": 1400, "height": 900})
    page.goto(html_path.as_uri())
    page.wait_for_timeout(800)
    page.screenshot(path=str(png_path), full_page=False)
    return png_path


def main():
    svgs  = sorted(OUT.glob("*.svg"))
    html  = BASE / "reports" / "report_demo.html"

    print(f"\nScreenshot tool — Playwright/Chromium\n")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page    = browser.new_page()

        for svg in svgs:
            png = screenshot_svg(page, svg)
            kb  = os.path.getsize(png) // 1024
            print(f"  [PNG] {png.name}  ({kb} KB)")

        if html.exists():
            png = screenshot_html(page, html)
            kb  = os.path.getsize(png) // 1024
            print(f"  [PNG] {png.name}  ({kb} KB)")
        else:
            print(f"  [SKIP] HTML report not found at {html}")

        browser.close()

    print(f"\nAll PNGs saved to: {OUT}")
    print("Done.")


if __name__ == "__main__":
    main()
