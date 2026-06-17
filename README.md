# NoChrome

A from-scratch browser project in C++ with SDL2, SDL2_ttf and sdl2_image.

**Goal:** evolve this project into a fully working browser over time, built step by step without embedding Chromium/WebKit.  
The current implementation is an early prototype of the rendering and UI pipeline.

## Current Features
- Windowed GUI with tabs (Ctrl+T new tab, Ctrl+W close tab, Ctrl+L focus address bar)
- HTTP and HTTPS page loading (OpenSSL) with chunked transfer decoding
- HTML-to-text rendering with inline images (PNG/JPEG via SDL2_image)
- Clickable links and trackpad-friendly scrolling
- CSS support (early v0.x)
  - tag, class, id and `tag.class` selectors, comma groups, inline styles
  - external stylesheets (`<link rel="stylesheet">`)
  - properties: `color`, `font-size`, `font-weight`, page `background`
- JavaScript support (JavaScriptCore on macOS, QuickJS elsewhere)
  - `console`, `alert`, `performance.now`, `setTimeout`/`clearTimeout`, `fetch` (Promise + `.then`)
  - DOM: `getElementById`, `querySelector("#id")`, `createElement`, `document.body`/`head`,
    `textContent`/`innerHTML`, `style.display`, `setAttribute`/`getAttribute`, `appendChild`
  - events: `window`/`document`/element `addEventListener` with `click` and `keydown` dispatch

## Limitations (Current Stage)
- No full DOM tree or box model layout (line-based rendering; HTML parsed best-effort)
- DOM mutations are applied to a backing HTML string, not a live tree
- JavaScript is a useful subset, not a complete engine integration:
  - no ES module loading, event bubbling, or `removeEventListener`
  - `querySelector` supports only `#id`
  - a single shared JS context (multi-tab JS is not isolated)
- No form controls / input widgets yet

## Requirements
- C++17 compiler
- CMake
- SDL2, SDL2_ttf, SDL2_image
- OpenSSL (for HTTPS)
- A JavaScript engine: JavaScriptCore (bundled on macOS) or QuickJS (other platforms)
- A TTF font (DejaVu Sans ships in `fonts/`; common system fonts are used as a fallback)

## Project Structure
```text
.
├── CMakeLists.txt
├── main.cpp
├── fonts/
│   └── DejaVuSans.ttf
└── README.md
```

## Build (macOS)
```bash
brew install cmake pkg-config sdl2 sdl2_ttf sdl2_image openssl@3 git quickjs
cmake -S . -B build
cmake --build build
```

## Build (Linux)
```bash
# Debian/Ubuntu
sudo apt-get install cmake g++ libsdl2-dev libsdl2-ttf-dev libsdl2-image-dev libssl-dev quickjs libquickjs

cmake -S . -B build
cmake --build build
```

## Run
```bash
./build/NoChrome http://example.com/
```

## Roadmap (High Level)

### 1) Solid Static Web Support
- HTML tokenizer + real DOM tree
- Better text nodes and whitespace handling
- External CSS loading
- Improved selector support (descendants, grouping, basic specificity)
- A minimal box model:
  - block/inline
  - margins/padding
  - background colors
  - per-line height based on font sizes

### 2) Real Networking
- Redirect handling (301/302/307/308)
- Content-Type based parsing
- Compression support (gzip/deflate)
- Character encoding handling
- **HTTPS** via a TLS library

### 3) Interactivity Foundations
- Form controls (input, button, textarea)
- Focus/selection basics
- Better link states (hover/active)

### 4) JavaScript (Long-Term)
- Integrate a JS engine (e.g., QuickJS or another embeddable engine)
- Minimal DOM bindings
- Event loop basics

### 5) Rendering Improvements
- Images (PNG/JPEG)
- More robust layout primitives
- Incremental reflow/paint

## Contributing
Issues and PRs are welcome.  
If you want to help, focus on small isolated improvements (parser, CSS rules, layout primitives, or networking).

## License
MIT
