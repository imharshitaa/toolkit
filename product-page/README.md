# ToolKit — Interactive Showcase (`product-page/`)

A static, interactive showcase site for the [ToolKit](https://github.com/imharshitaa/toolkit) CLI.
Pure HTML/CSS/vanilla JS — no backend, no build step, no dependencies to install.

It is **not** a hosted version of the CLI. The Command Console, Sample Report Preview, and
Authorization Checker are client-side demonstrations built directly from the real Python source
(`toolkit/*.py` and `modules/*/*/*.py`) — every flag, default, dashboard URL, and error string is
transcribed from the actual implementation, not invented. Simulated/sample output is always
clearly labeled as such in the UI. Nothing on this page executes a scan, deploys a container, or
makes a network call — to actually run ToolKit, install it locally (instructions are in the
page's footer and in the repo's main README).

## Files

```
product-page/
├── index.html        Page structure and content
├── assets/
│   ├── style.css      All styling (dark SOC/security-dashboard theme)
│   ├── data.js        Tool/module/flag data model, mirrored from the Python CLI definitions
│   └── script.js      Interactive logic (console, reports, auth checker, nav, animations)
└── README.md          This file
```

## Preview locally

No build tooling is required — any static file server works, e.g.:

```bash
cd product-page
python3 -m http.server 8080
# then open http://localhost:8080
```

Opening `index.html` directly via `file://` also works, since there are no absolute paths or
server-side includes.

## Publish with GitHub Pages

This site is designed to be served as a **subpath of the main `toolkit` repository**, at
`https://imharshitaa.github.io/toolkit/product-page/`. To enable it:

1. Push this `product-page/` directory to the `main` branch of
   `https://github.com/imharshitaa/toolkit` (already done if you're reading this from the repo).
2. On GitHub, go to the repository's **Settings → Pages**.
3. Under **Build and deployment → Source**, choose **Deploy from a branch**.
4. Set **Branch** to `main` and **Folder** to `/ (root)`, then **Save**.
5. Wait a minute or two for the first deployment to finish (check the **Pages** section or the
   **Actions** tab for the "pages build and deployment" workflow run).
6. The site will be live at:
   - Repo root (README rendering, if you ever add a root `index.html`): `https://imharshitaa.github.io/toolkit/`
   - This showcase: **`https://imharshitaa.github.io/toolkit/product-page/`**

No GitHub Actions workflow, Jekyll config, or `_config.yml` is needed — all paths in `index.html`
are relative (`assets/style.css`, `assets/data.js`, `assets/script.js`), so the page works
identically whether it's served from the repo root or from the `/product-page/` subpath.

## Keeping it in sync with the CLI

If you add or change a CLI flag, tool capability, dashboard URL, or error message in the Python
source, update the corresponding entry in `assets/data.js` (and, if the console's rendering logic
needs to change, `assets/script.js`) so the showcase doesn't drift from the real implementation.
