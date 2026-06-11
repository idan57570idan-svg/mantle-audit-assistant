"""
Generates a demo GIF/video of the terminal output using Playwright frames.
Captures real output from main.py demo and animates it line by line.
"""
import os
import sys
import subprocess
import re
import imageio.v3 as iio
import numpy as np
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE    = Path(__file__).parent
FRAMES  = BASE / "demo_frames"
OUT_GIF = BASE / "demo_screenshots" / "demo_animation.gif"
OUT_MP4 = BASE / "demo_screenshots" / "demo_video.mp4"
W, H    = 1100, 720

FRAMES.mkdir(exist_ok=True)


# ── ANSI colour map → CSS ─────────────────────────────────────────────────────
ANSI_CSS = {
    "bold":    "font-weight:bold",
    "red":     "color:#ff5555",
    "green":   "color:#50fa7b",
    "yellow":  "color:#f1fa8c",
    "cyan":    "color:#8be9fd",
    "blue":    "color:#bd93f9",
    "magenta": "color:#ff79c6",
    "white":   "color:#f8f8f2",
    "dim":     "color:#6272a4",
}

def ansi_to_html(text: str) -> str:
    """Very light ANSI-escape → styled HTML spans."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # colour codes
    text = re.sub(r'\x1b\[(\d+)m', lambda m: _ansi_tag(m.group(1)), text)
    text = re.sub(r'\x1b\[0m',  '</span>', text)
    text = re.sub(r'\x1b\[\d+;\d+m', '', text)   # combined codes — strip
    text = re.sub(r'\x1b\[[^m]+m', '', text)       # remaining — strip
    return text

def _ansi_tag(code: str) -> str:
    MAP = {
        "1":"bold","31":"red","32":"green","33":"yellow",
        "34":"blue","35":"magenta","36":"cyan","37":"white","2":"dim",
        "91":"red","92":"green","93":"yellow","96":"cyan",
    }
    style = ANSI_CSS.get(MAP.get(code, ""), "")
    return f'<span style="{style}">' if style else '<span>'


TERMINAL_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background:#0d1117; color:#c9d1d9;
    font-family:'Cascadia Code','Fira Mono','Consolas',monospace;
    font-size:13.5px; line-height:1.55;
    width:{W}px; height:{H}px; overflow:hidden;
  }}
  .titlebar {{
    background:#161b22; padding:8px 16px; border-bottom:1px solid #30363d;
    display:flex; align-items:center; gap:8px;
  }}
  .dot {{ width:12px; height:12px; border-radius:50%; }}
  .r {{ background:#ff5f56; }} .y {{ background:#ffbd2e; }} .g {{ background:#27c93f; }}
  .title {{ color:#8b949e; font-size:12px; margin-left:8px; }}
  .terminal {{
    padding:14px 18px; height:calc(100% - 37px);
    overflow:hidden; white-space:pre-wrap; word-break:break-all;
  }}
  .cursor {{ display:inline-block; width:8px; height:14px;
             background:#c9d1d9; vertical-align:text-bottom;
             animation:blink 1s step-end infinite; }}
  @keyframes blink {{ 50%{{ opacity:0; }} }}
</style>
</head>
<body>
<div class="titlebar">
  <div class="dot r"></div><div class="dot y"></div><div class="dot g"></div>
  <div class="title">PowerShell — Mantle Smart Contract Audit Assistant</div>
</div>
<div class="terminal" id="term">{content}<span class="cursor"></span></div>
</body></html>"""


def get_demo_lines() -> list[str]:
    """Run the actual demo and collect output lines."""
    print("  Running demo to capture output...")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["FORCE_COLOR"] = "1"
    env["TERM"] = "xterm-256color"
    result = subprocess.run(
        [sys.executable, "main.py", "demo"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=env, cwd=str(BASE)
    )
    raw = (result.stdout + result.stderr).splitlines()
    print(f"  Captured {len(raw)} lines.")
    return raw


def render_frame(page, lines_so_far: list[str], frame_idx: int) -> np.ndarray:
    content = "<br>".join(ansi_to_html(l) for l in lines_so_far[-46:])  # last 46 lines visible
    html    = TERMINAL_HTML.format(content=content, W=W, H=H)
    page.set_content(html)
    png_bytes = page.screenshot(clip={"x": 0, "y": 0, "width": W, "height": H})
    arr = np.frombuffer(png_bytes, dtype=np.uint8)
    import PIL.Image, io
    img = PIL.Image.open(io.BytesIO(png_bytes)).convert("RGB")
    return np.array(img)


def build_frames(lines: list[str]) -> list[np.ndarray]:
    """Build animation frames: reveal lines progressively."""
    frames   = []
    shown    = []

    # Intro frame: just the prompt
    intro = ["", "  PS C:\\Users\\USER\\Desktop\\אקטון> python main.py demo", ""]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page    = browser.new_page()
        page.set_viewport_size({"width": W, "height": H})

        # Hold intro for ~1.5 s (= 5 frames × 300 ms)
        frame = render_frame(page, intro, 0)
        for _ in range(5):
            frames.append(frame)

        shown = intro[:]

        step = 1   # reveal 1 line per frame (will skip blanks in batches)
        i = 0
        max_lines = min(len(lines), 180)  # keep first 180 lines for a tight demo
        while i < max_lines:
            line = lines[i]
            shown.append(line)
            i += 1

            # Batch consecutive blank lines (don't pause on them)
            if line.strip() == "":
                while i < len(lines) and lines[i].strip() == "":
                    shown.append(lines[i])
                    i += 1
                frames.append(render_frame(page, shown, len(frames)))
                continue

            frames.append(render_frame(page, shown, len(frames)))

            # Extra hold on separator lines and headers
            if set(line.strip()) <= set("-=+|#") and len(line.strip()) > 10:
                frames.append(frames[-1])

        # Hold final frame for 3 s
        for _ in range(10):
            frames.append(frames[-1])

        browser.close()

    return frames


def main():
    print("\nBuilding demo animation...\n")
    lines  = get_demo_lines()
    print("  Rendering frames with Playwright...")
    frames = build_frames(lines)
    print(f"  Generated {len(frames)} frames.")

    # ── GIF (every other frame to keep size down) ─────────────────────────────
    print(f"  Writing GIF -> {OUT_GIF}")
    gif_frames = frames[::2]   # half the frames for smaller file
    iio.imwrite(str(OUT_GIF), gif_frames, format="GIF",
                duration=200,  # ms per frame
                loop=0)
    print(f"  GIF size: {os.path.getsize(OUT_GIF) // 1024} KB")

    # ── MP4 via imageio-ffmpeg ────────────────────────────────────────────────
    try:
        print(f"  Writing MP4 -> {OUT_MP4}")
        writer = iio.imopen(str(OUT_MP4), "w", plugin="pyav")
        writer.write(np.stack(frames), fps=8, codec="libx264",
                     output_params=["-crf", "28", "-pix_fmt", "yuv420p"])
        writer.close()
        print(f"  MP4 size: {os.path.getsize(OUT_MP4) // 1024} KB")
    except Exception as e:
        print(f"  MP4 skipped ({e}) — GIF is the primary output.")

    print(f"\nDone! Files in demo_screenshots/")
    print(f"  demo_animation.gif  - upload anywhere")
    print(f"  demo_video.mp4      - upload to YouTube Unlisted")


if __name__ == "__main__":
    main()
