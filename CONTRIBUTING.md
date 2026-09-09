# Contributing to Crypto Toolbox

This project is a **local, offline toolbox** for cryptography and crypto forensics. Keeping it simple, self-contained, and private is more important than adding features fast. Please read the short guidelines below before opening a pull request.

## Guidelines

### 1. Follow the existing structure

Look at how the current tools are built and match that style — don't invent a new
pattern.

- Every tool lives in its own folder: `tools/<your-tool>/`.
- Inside it you keep your own `HTML`, `JS`, and `CSS` (same as the other tools).
- Register the tool with a button in `Toolbox.html` using
  `data-type="frame"` and `data-src="tools/<your-tool>/<file>.html"`.
- Sync with the app theme by listening for the `postMessage` event
  (`source: 'cryptotoolbox'`, `type: 'theme'`) — copy this from an existing tool.

If a new tool looks and behaves like the ones already in the repo, you're on the
right track.

### 2. Every tool must work on its own (self-contained)

This is the most important rule. Each tool is loaded in its own `<iframe>` and must run
**completely independently** — exactly like the tools already in the repo.

Concretely, that means:

- **Open it directly and it works.** Opening `tools/<your-tool>/<file>.html` on its own
  in a browser must fully work, with no build step and no server.
- **No dependency on other tools.** A tool must never import, call, or rely on code from
  another tool's folder, or on shared parent scripts. If it breaks when another tool is
  removed, it isn't self-contained.
- **Bundle everything locally.** All libraries go inside the tool's own folder (see how
  other tools keep dependencies in a `vendor/` folder). **No CDN links, no external
  `<script src="https://...">`.** The app must keep working with no internet connection.
- **Talk to the app only through the theme message.** The single allowed link to the
  parent is the theme `postMessage` above — nothing else.

In short: if someone copied your tool folder out of the project, it should still run.

### 3. Keep it offline and private

This toolbox handles sensitive data (seed phrases, private keys, wallet files). Because
of that:

- **No network requests.** No fetch/XHR to remote servers, no telemetry, no analytics,
  no phoning home. Everything runs on the user's machine.
- **No secrets leave the tool.** Never log, upload, or store keys/seeds anywhere outside
  the tool the user is actively using.

If your tool cannot do its job without going online, it doesn't fit this project.

### 4. Credit third-party code

If you reuse someone else's library or code, keep it in your tool's folder and add a line
to the **Attribution** section in `README.md` with a link to the source.

## Before you open a pull request

A quick checklist:

- [ ] The tool lives in its own `tools/<name>/` folder.
- [ ] Opening its HTML file directly works, with no server and no internet.
- [ ] No calls to other tools or external URLs; dependencies are bundled locally.
- [ ] It's registered in `Toolbox.html` and follows the theme (light/dark).
- [ ] You tested it with `npm start` and it looks/behaves like the other tools.
- [ ] Any third-party code is credited in `README.md`.

Keep pull requests small and focused — one tool or one fix at a time is easiest to
review.
