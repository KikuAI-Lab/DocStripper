<div align="center">
  <img src="docs/assets/icon.svg?v=2" alt="DocStripper Logo" width="120">
  
  # 🧹 DocStripper
  
  > **Batch document cleaner for TXT, DOCX and PDF text** — Rule-based cleanup with an optional browser AI mode
</div>

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![Product Hunt](https://img.shields.io/badge/Product%20Hunt-Featured-orange)](https://www.producthunt.com/products/docstripper)

**DocStripper** removes common text noise such as page numbers, headers/footers, duplicate lines, and empty lines. The browser app offers rule-based **Fast Clean** and optional **Smart Clean (Beta)** with an on-device model; the Python CLI uses rule-based text processing. DOCX and PDF support means text extraction, not preservation of the original document layout.

In the web app, DocStripper processes selected document files in your browser and does not upload their contents. The page still makes network requests for third-party resources, analytics, translation, and Smart Clean model downloads. No account is required.

**🌐 [Try it online →](https://kikuai-lab.github.io/DocStripper/)** — No installation needed!

**📦 Latest Release:** [v2.1.0](https://github.com/KikuAI-Lab/DocStripper/releases/tag/v2.1.0) — UX enhancements & distribution ready

---

## ✨ Features

- ⚡ **Fast Clean** — Instant rule-based cleaning
- 🤖 **Smart Clean (Beta)** — AI-powered cleaning with on-device LLM
- 🎚️ **4 Cleaning Temperaments** — Gentle (safe), Moderate, Thorough, Aggressive
- ⚙️ **WebWorker Processing** — Large files processed in background (no UI freezing)
- 🔄 **Side-by-Side Preview** — Compare Original | Cleaned
- 💾 **Settings Persistence** — Your preferences are saved automatically
- 🔒 **Local File Processing** — DocStripper processes selected files in the browser and does not upload their contents
- 📊 **Real-time Statistics** — See exactly what was removed
- 📥 **Batch Download (ZIP)** — Download multiple cleaned files at once
- 🎨 **Dark Theme** — Toggle between light and dark themes
- 📱 **Mobile Responsive** — Works great on mobile devices

---

## 🎯 Quick Start

### Web App (Recommended)

1. Visit [https://kikuai-lab.github.io/DocStripper/](https://kikuai-lab.github.io/DocStripper/)
2. Choose your local files
3. Choose **Fast Clean** (rule-based) or **Smart Clean (Beta)** (AI-powered)
4. Adjust **Cleaning Temperament** slider: Gentle (recommended), Moderate, Thorough, or Aggressive
5. Click "Start Cleaning"
6. Review the preview, then download or copy the cleaned results

### CLI Tool

> [!WARNING]
> Start with `--dry-run` and copies of your files. Without `--dry-run` or
> `--stdout`, the current CLI writes cleaned **plain text back to the input
> path**, including a `.docx` or `.pdf` path. It does not rebuild those document
> formats. Do not use in-place cleaning on original DOCX/PDF files.

#### Installation Options

**Option 1: Homebrew (macOS)**
```bash
brew tap KikuAI-Lab/docstripper
brew install docstripper
docstripper --dry-run document.txt
```

**Option 2: Manual Installation**
```bash
git clone https://github.com/KikuAI-Lab/DocStripper.git
cd DocStripper
python3 tool.py --dry-run document.txt
```

Replace `document.txt` with a copy of an existing local file. See
[INSTALL.md](INSTALL.md) for detailed installation instructions. CLI PDF text
extraction requires `pdftotext`; see [Supported Formats](#️-supported-formats).

#### Usage

```bash
# Preview changes without modifying the input
python3 tool.py --dry-run document.txt

# Preview multiple inputs without overwriting their formats
python3 tool.py --dry-run file1.txt file2.txt file3.docx

# Inspect PDF text in the terminal without modifying the source PDF
python3 tool.py --keep-headers input.pdf --stdout

# Only after reviewing: clean a disposable plain-text copy in place
python3 tool.py document-copy.txt

# Attempt to restore the last logged in-place operation from its backup
python3 tool.py --undo
```

**Current CLI I/O limitations:** `--stdout` avoids modifying the input, but
progress messages, separators, and statistics also go to stdout. Do not treat
redirected output as a clean machine-readable transcript. The CLI entry point
currently checks `-` as a filesystem path, so piped stdin is not a working
entry point; pass an existing filename instead. Piping raw PDF bytes would not
perform PDF extraction either. These are implementation limitations, not
features fixed by this documentation.

---

## 📖 Example

**Before:**
```
Page 1 of 10
Confidential - Internal Use Only
Executive Summary
This is auto-
matic text processing.
Important content here.
Important content here.

1
2
3
```

**After (Gentle Mode):**
```
Executive Summary
This is automatic text processing.
Important content here.
```

**Key Changes:**
- ✅ Page numbers removed
- ✅ Headers/footers removed
- ✅ Repeating headers removed
- ✅ Duplicates collapsed
- ✅ Hyphenation fixed
- ✅ Empty lines removed

---

## 🎨 What Gets Removed?

### Cleaning Temperaments

**Gentle (Recommended - Default)**
- ✅ Page numbers (1, 2, 3...)
- ✅ Headers/footers ("Page X of Y", "Confidential", etc.)
- ✅ Repeating headers/footers across pages
- ✅ Duplicate lines
- ✅ Empty lines
- ✅ Punctuation-only lines (---, ***, ===)
- ✅ Hyphenation fixed (auto-\nmatic → automatic)
- ✅ Preserves paragraph spacing
- ❌ Line merging disabled (preserves formatting)
- ❌ Whitespace normalization disabled
- ❌ Unicode normalization disabled

**Moderate**
- All Gentle features plus:
- ✅ Merges broken lines (protects lists and tables)
- ✅ Preserves paragraph spacing

**Thorough**
- All Moderate features plus:
- ✅ Normalizes whitespace (protects tables)
- ✅ Normalizes Unicode punctuation (smart quotes, dashes → ASCII)
- ✅ Preserves paragraph spacing (better readability)

**Aggressive**
- All Thorough features plus:
- ✅ Normalizes Unicode punctuation
- ❌ Removes paragraph spacing (more compact output)

### CLI Flags (defaults ON)
- `--no-merge-lines` — disable merging broken lines
- `--no-dehyphenate` — disable de-hyphenation across line breaks
- `--no-normalize-ws` — disable whitespace normalization
- `--no-normalize-unicode` — disable Unicode punctuation normalization
- `--keep-headers` — keep headers/footers/page numbers
- `--stdout` — print cleaned text without modifying the input; currently also includes diagnostics (see CLI I/O limitations above)

**Protection Features:**
- ✅ Lists are never merged or broken
- ✅ Tables preserve spacing
- ✅ Content headers never removed

---

## 🛠️ Supported Formats

| Format | Status | Notes |
|--------|--------|-------|
| `.txt` | ✅ Full | UTF-8, Latin-1 |
| `.docx` | ✅ Basic | Text extraction only (Web + CLI); use a non-writing CLI mode to preserve the source document |
| `.pdf` | ✅ Basic | Text extraction only (Web + CLI). Web uses PDF.js automatically. CLI requires `pdftotext` (poppler-utils); use a non-writing CLI mode to preserve the source document |

**PDF Support:**
- macOS: `brew install poppler`
- Ubuntu/Debian: `sudo apt-get install poppler-utils`
- Windows: Download from [poppler-windows releases](https://github.com/oschwartz10612/poppler-windows/releases/)

---

## 🔧 Requirements

### Web App
- Modern web browser (Chrome, Firefox, Safari, Edge)
- No installation or dependencies required
- DocStripper does not upload selected document files
- Network access is used for page resources and Smart Clean model downloads

### CLI Tool
- **Python 3.9+** (for CLI tool)
- **PDF support** (optional): `pdftotext` from poppler-utils

---

## 📝 Changelog

See [GitHub Releases](https://github.com/KikuAI-Lab/DocStripper/releases) for release notes and changelog.

---

## 📝 License

MIT License — see [LICENSE.txt](LICENSE.txt) for details.

---

## 🤝 Contributing

Contributions are welcome! See [Contributing Guide](https://github.com/KikuAI-Lab/DocStripper/wiki/Contributing) for guidelines.

---

<div align="center">

**Made with ❤️ for clean documents**

[⭐ Star this repo](https://github.com/KikuAI-Lab/DocStripper) | [🌐 Try online](https://kikuai-lab.github.io/DocStripper/) | [🚀 Product Hunt](https://www.producthunt.com/products/docstripper) | [🐛 Report Bug](https://github.com/KikuAI-Lab/DocStripper/issues)

---

## 💝 Support

Support this project and help keep it free:

[☕ Support on Gumroad](https://kiku0.gumroad.com/coffee) | [☕ Buy Me a Coffee](https://buymeacoffee.com/kiku) | [🙏 Thanks.dev](https://thanks.dev/d/gh/kiku-jw) | [💚 Ko-fi](https://ko-fi.com/kiku_jw)

## 🔗 Connect

- 📰 **Blog & Updates**: [t.me/kiku_ai](https://t.me/kiku_ai)
- 💬 **Discord**: [discord.gg/4Kxs97JvsU](https://discord.gg/4Kxs97JvsU)
- 💼 **LinkedIn**: [linkedin.com/in/kiku-jw](https://www.linkedin.com/in/kiku-jw/)
- 🌐 **About.me**: [about.me/kiku_jw](https://about.me/kiku_jw)

</div>

<!-- author-links:start -->
<p align="center">
  <a href="https://kikuai.dev/"><img src="https://img.shields.io/badge/Website-kikuai.dev-111827?style=for-the-badge&logo=safari&logoColor=white" alt="KikuAI website"></a>
  <a href="https://t.me/kiku_ai"><img src="https://img.shields.io/badge/Telegram-%40kiku__ai-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram @kiku_ai"></a>
  <a href="https://github.com/kiku-jw"><img src="https://img.shields.io/badge/GitHub-%40kiku--jw-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub @kiku-jw"></a>
</p>
<p align="center">
  <sub>Follow new projects and updates from <a href="https://github.com/kiku-jw">@kiku-jw</a>.</sub>
</p>
<!-- author-links:end -->
