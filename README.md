# NoChrome

A from-scratch browser project in C++ with SDL2, SDL2_ttf and sdl2_image.

**Goal:** evolve this project into a fully working browser over time, built step by step without embedding Chromium/WebKit.  
The current implementation is an early prototype of the rendering and UI pipeline.

## Current Features
- Windowed GUI
- Address bar (Ctrl+L to focus)
- HTTPS page loading
- Basic HTML-to-text rendering
- Clickable links
- Trackpad-friendly scrolling
- Basic CSS support (early v0.x)
  - tag selectors (`h1`, `p`, `a`, ...)
  - class selectors (`.card`)
  - id selectors (`#main`)
  - `tag.class` selectors (`div.card`)
  - comma groups (`h1, h2 { ... }`)
  - inline styles
  - properties: `color`, `font-size`, `font-weight`
- Simple spacing heuristics for headings/paragraphs

## Limitations (Current Stage)
- No HTTPS
- No JavaScript execution
- No full DOM/box model layout
- No external stylesheets (`<link rel="stylesheet">`) yet
- Rendering is text-focused with line-based layout

## Requirements
- C++17 compiler
- CMake
- SDL2
- SDL2_ttf
- A TTF font file (recommended: `fonts/DejaVuSans.ttf`)

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
sudo apt-get install cmake g++ libsdl2-dev libsdl2-ttf-dev libsdl2-image-dev libssl-dev quickjs
sudo apt install libssl-dev

cmake -S . -B build
cmake --build build
```

## Run
```bash
./build/TinyGuiBrowser http://example.com/
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
