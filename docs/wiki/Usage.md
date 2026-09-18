# Usage Guide

## Web Application

### Quick Start

1. Visit https://kikuai-lab.github.io/DocStripper/
2. Click "Upload Your Documents" or drag & drop files
3. Choose cleaning mode:
   - **Fast Clean**: Instant rule-based cleaning
   - **Smart Clean**: AI-powered cleaning (requires WebGPU)
4. Configure cleaning options
5. Click "Start Cleaning"
6. Download or copy the cleaned results

### Cleaning Modes

#### Fast Clean
- **Speed**: Instant
- **Method**: Rule-based pattern matching
- **Best for**: Standard documents with predictable patterns

#### Smart Clean (Beta)
- **Speed**: Slower (depends on document size)
- **Method**: AI-powered with on-device LLM
- **Requirements**: WebGPU support, ~100-200 MB one-time download
- **Best for**: Complex documents with unusual patterns

### Cleaning Options

- **Remove Empty Lines**: Removes blank and whitespace-only lines
- **Remove Page Numbers**: Removes lines with only digits (1, 2, 3...)
- **Remove Headers/Footers**: Removes common patterns (Page X of Y, Confidential, etc.)
- **Remove Duplicates**: Collapses consecutive identical lines
- **Remove Punctuation Lines**: Removes lines with only symbols (---, ***, ===)
- **Preserve Paragraph Spacing**: Keeps one empty line between paragraphs

## CLI Tool

> [!WARNING]
> Use copies and start with `--dry-run`. Without `--dry-run` or `--stdout`,
> the current CLI overwrites the input path with plain text. DOCX/PDF inputs
> are not rebuilt as DOCX/PDF documents. Do not use in-place cleaning on
> original files in those formats.

### Basic Usage

```bash
# Preview a single file without modifying it
python3 tool.py --dry-run document.txt

# Preview multiple files without changing their formats
python3 tool.py --dry-run file1.txt file2.txt file3.docx

# Inspect cleaned text in the terminal without modifying the input
python3 tool.py document.txt --stdout

# Attempt to restore the last logged in-place operation from its backup
python3 tool.py --undo
```

### Supported Formats

- `.txt` - Plain text files
- `.docx` - Text extraction from Microsoft Word documents; layout is not preserved
- `.pdf` - Text extraction from PDF files; requires `pdftotext` from poppler-utils

### Command Options

```text
python3 tool.py [OPTIONS] [FILES...]

Options:
  -h, --help     Show help message
  --dry-run      Preview diagnostics without modifying files
  --undo         Restore files from the last logged operation when backups exist
  --stdout       Print cleaned text and diagnostics without modifying the input
  --keep-headers Keep headers/footers/page numbers
  --no-merge-lines        Disable merging broken lines
  --no-dehyphenate        Disable de-hyphenation across line breaks
  --no-normalize-ws       Disable whitespace normalization
  --no-normalize-unicode  Disable Unicode punctuation normalization
```

### Examples

#### Example 1: Clean a disposable plain-text copy
```bash
cp report.txt report-copy.txt
python3 tool.py --dry-run report-copy.txt
# Run only after reviewing the preview:
python3 tool.py report-copy.txt
```

#### Example 2: Inspect multiple documents without overwriting them
```bash
python3 tool.py --dry-run document1.txt document2.docx document3.pdf
```

#### Example 3: Keep headers during inspection
```bash
python3 tool.py --keep-headers important_document.txt --stdout
```

#### Example 4: Undo the last logged in-place operation
```bash
python3 tool.py --undo
```

#### Example 5: Inspect extracted PDF text
```bash
python3 tool.py report.pdf --stdout
```

### Current I/O limitations

The main entry point checks `-` as a filesystem path, so normal piped stdin is
not currently supported. Pass an existing filename. Raw PDF bytes must go
through the PDF extraction path, not through a text decoder.

The `--stdout` path currently includes progress messages, separators, and final
statistics. Redirecting it to a file does not produce a clean transcript for
another program. This documentation does not fix the CLI implementation; it
avoids advertising unsupported pipeline behavior.

### Output and backups

For normal in-place processing, the tool creates `.bak` files, writes cleaned
plain text over the originals, and logs operations in `.strip-log`. Keep an
independent copy: repeated operations may replace a previous backup. Restoring
with `--undo` depends on the relevant log and backup files still being present.

`--dry-run` does not write a cleaned input file. `--stdout` also avoids modifying
the input, but includes the diagnostic output described above.

## Best Practices

1. **Always test on copies first** - Start with `--dry-run`.
2. **Keep independent backups** - A `.bak` file is not a replacement for versioned originals.
3. **Review the extracted text** - DOCX/PDF support does not preserve layout or formatting.
4. **Choose the correct surface** - Browser modes and Python CLI behavior are not identical.

## Troubleshooting

See [Troubleshooting Guide](Troubleshooting) for common issues and solutions.
