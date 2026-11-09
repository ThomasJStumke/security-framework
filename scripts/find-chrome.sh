#!/usr/bin/env bash
# Prints the path of a Chrome/Chromium that Lighthouse can drive: Playwright's chromium when the
# runner already has one, a system browser, else installs Playwright's chromium. Prints nothing if none.
find_one() {
  ls -d "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux*/chrome 2>/dev/null | sort -V | tail -1
}
c="$(find_one)"
[ -z "$c" ] && c="$(command -v google-chrome-stable google-chrome chromium chromium-browser 2>/dev/null | head -1)"
if [ -z "$c" ]; then
  npx --yes playwright install chromium >/dev/null 2>&1 || true
  c="$(find_one)"
fi
printf '%s' "$c"
