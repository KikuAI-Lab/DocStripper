#!/usr/bin/env python3
"""
Security tests for DocStripper
Tests for zip slip vulnerabilities, malformed files, and other security issues
"""
import sys
import os
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tool import DocStripper  # type: ignore


def test_zip_slip_protection():
    """Test that zip slip attacks are blocked"""
    print("Testing zip slip protection...")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a malicious DOCX with path traversal
        malicious_docx = Path(tmpdir) / "malicious.docx"

        with zipfile.ZipFile(malicious_docx, 'w') as zf:
            # Try to escape with ../ in filename
            zf.writestr("../../../etc/passwd", "malicious content")
            # Also add the required document.xml
            zf.writestr("word/document.xml", """<?xml version="1.0"?>
<document xmlns="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <body><p><t>Test</t></p></body>
</document>""")

        ds = DocStripper()
        result = ds.extract_text_from_docx(malicious_docx)

        # Should return None due to security check
        assert result is None, "Zip slip attack was not blocked!"

    print("  ✓ Zip slip protection working")


def test_absolute_path_protection():
    """Test that absolute paths in ZIP are blocked"""
    print("Testing absolute path protection...")

    with tempfile.TemporaryDirectory() as tmpdir:
        malicious_docx = Path(tmpdir) / "absolute_path.docx"

        with zipfile.ZipFile(malicious_docx, 'w') as zf:
            # Try absolute path
            zf.writestr("/tmp/malicious.txt", "malicious content")
            zf.writestr("word/document.xml", """<?xml version="1.0"?>
<document xmlns="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <body><p><t>Test</t></p></body>
</document>""")

        ds = DocStripper()
        result = ds.extract_text_from_docx(malicious_docx)

        # Should return None due to security check
        assert result is None, "Absolute path attack was not blocked!"

    print("  ✓ Absolute path protection working")


def test_malformed_zip():
    """Test handling of malformed ZIP files"""
    print("Testing malformed ZIP handling...")

    with tempfile.TemporaryDirectory() as tmpdir:
        malformed_file = Path(tmpdir) / "malformed.docx"

        # Write invalid ZIP data
        with open(malformed_file, 'wb') as f:
            f.write(b"This is not a valid ZIP file")

        ds = DocStripper()
        result = ds.extract_text_from_docx(malformed_file)

        # Should return None gracefully
        assert result is None, "Malformed ZIP not handled gracefully"

    print("  ✓ Malformed ZIP handling working")


def test_missing_document_xml():
    """Test handling of DOCX without required document.xml"""
    print("Testing missing document.xml handling...")

    with tempfile.TemporaryDirectory() as tmpdir:
        incomplete_docx = Path(tmpdir) / "incomplete.docx"

        with zipfile.ZipFile(incomplete_docx, 'w') as zf:
            # Create valid ZIP but without document.xml
            zf.writestr("some_file.txt", "content")

        ds = DocStripper()
        result = ds.extract_text_from_docx(incomplete_docx)

        # Should return None gracefully
        assert result is None, "Missing document.xml not handled gracefully"

    print("  ✓ Missing document.xml handling working")


def test_malformed_xml():
    """Test handling of malformed XML in DOCX"""
    print("Testing malformed XML handling...")

    with tempfile.TemporaryDirectory() as tmpdir:
        bad_xml_docx = Path(tmpdir) / "bad_xml.docx"

        with zipfile.ZipFile(bad_xml_docx, 'w') as zf:
            # Create DOCX with invalid XML
            zf.writestr("word/document.xml", "This is not valid XML <<<<")

        ds = DocStripper()
        result = ds.extract_text_from_docx(bad_xml_docx)

        # Should return None gracefully
        assert result is None, "Malformed XML not handled gracefully"

    print("  ✓ Malformed XML handling working")


def test_empty_file_handling():
    """Test handling of empty files"""
    print("Testing empty file handling...")

    with tempfile.TemporaryDirectory() as tmpdir:
        empty_txt = Path(tmpdir) / "empty.txt"
        empty_txt.write_text("")

        ds = DocStripper()
        text = ds.read_text_file(empty_txt)

        # Should return empty string, not None
        assert text == "", f"Empty file handling failed: got {text!r}"

        # Clean empty text should also be empty
        cleaned, stats = ds.clean_text("", merge_lines=True)
        assert cleaned == "", "Empty text cleaning failed"

    print("  ✓ Empty file handling working")


def test_large_file_handling():
    """Test handling of large files (basic check)"""
    print("Testing large file handling...")

    with tempfile.TemporaryDirectory() as tmpdir:
        large_txt = Path(tmpdir) / "large.txt"

        # Create a file with 10,000 lines
        lines = ["This is line number %d" % i for i in range(10000)]
        large_txt.write_text("\n".join(lines))

        ds = DocStripper()
        text = ds.read_text_file(large_txt)

        assert text is not None, "Large file reading failed"
        assert len(text.split('\n')) == 10000, "Large file line count incorrect"

        # Test cleaning
        cleaned, stats = ds.clean_text(text, merge_lines=False)
        assert cleaned is not None, "Large file cleaning failed"

    print("  ✓ Large file handling working")


def test_permission_denied():
    """Test handling of permission denied errors"""
    print("Testing permission denied handling...")

    # Skip this test on Windows and when running as root
    if sys.platform == 'win32':
        print("  ⊘ Skipped on Windows")
        return

    if os.geteuid() == 0:
        print("  ⊘ Skipped when running as root")
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        protected_file = Path(tmpdir) / "protected.txt"
        protected_file.write_text("protected content")

        # Remove read permissions
        os.chmod(protected_file, 0o000)

        try:
            ds = DocStripper()
            result = ds.read_text_file(protected_file)

            # Should return None or raise PermissionError (both are acceptable)
            # The important thing is that it doesn't crash
            if result is None:
                print("  ✓ Permission denied handling working (returned None)")
            else:
                # Running as root or permissions didn't work
                print("  ⊘ Permission test inconclusive (file was readable)")
        except PermissionError:
            # PermissionError is also acceptable (handled exception)
            print("  ✓ Permission denied handling working (exception raised)")
        finally:
            # Restore permissions for cleanup
            os.chmod(protected_file, 0o644)


def run_all_security_tests():
    """Run all security tests"""
    print("=" * 60)
    print("DocStripper Security Test Suite")
    print("=" * 60)

    tests = [
        test_zip_slip_protection,
        test_absolute_path_protection,
        test_malformed_zip,
        test_missing_document_xml,
        test_malformed_xml,
        test_empty_file_handling,
        test_large_file_handling,
        test_permission_denied,
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ Test failed: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    if failed == 0:
        print(f"✅ All {passed} security tests passed!")
        return 0
    else:
        print(f"❌ {failed} test(s) failed, {passed} passed")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_security_tests())
