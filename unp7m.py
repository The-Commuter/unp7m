#!/usr/bin/env python3
"""
unp7m - Extract PDF from .p7m files and display signature information.

Behavior:
  - Terminal (CLI):   prints signature info to stdout, extracts PDF
  - Double-click / "Open with" (macOS): extracts PDF, creates .log file

Usage:
    unp7m file.pdf.p7m              # extract PDF, print signature info
    unp7m file.pdf.p7m -o out.pdf   # extract to specific path
    unp7m file.pdf.p7m --no-extract # only show signature info
    unp7m file.pdf.p7m --json       # output as JSON
"""

import sys
import os
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add script/bundle directory to path for imports
if getattr(sys, 'frozen', False):
    _bundle_dir = Path(sys._MEIPASS)
else:
    _bundle_dir = Path(__file__).parent
sys.path.insert(0, str(_bundle_dir))

# Default CA bundle: look in bundle dir (PyInstaller) or script dir
_DEFAULT_CA_BUNDLE = _bundle_dir / "ca-italiane.pem"
if not _DEFAULT_CA_BUNDLE.exists():
    _DEFAULT_CA_BUNDLE = None

from verify_signature import (
    verify_cades_all_levels,
    get_extracted_filename,
    detect_signature_type,
)


def _is_terminal():
    """Check if running in an interactive terminal."""
    try:
        return sys.stdout.isatty() and sys.stderr.isatty()
    except Exception:
        return False


def _format_signer(signer):
    """Format signer info as dict."""
    if not signer:
        return None
    return {
        k: v for k, v in {
            "full_name": signer.full_name,
            "common_name": signer.common_name,
            "given_name": signer.given_name,
            "surname": signer.surname,
            "organization": signer.organization,
            "serial_number": signer.serial_number,
            "email": signer.email,
        }.items() if v
    }


def format_results_text(results):
    """Format signature results as human-readable text."""
    lines = []
    total = len(results)
    lines.append(f"Signatures found: {total}{' (nested)' if total > 1 else ''}")
    lines.append("")

    for r in results:
        if total > 1:
            lines.append(f"--- Level {r.level} ---")

        status = "VALID" if r.is_valid else "INVALID"
        lines.append(f"  Status:      {status}")
        lines.append(f"  Chain:       {'Valid' if r.certificate_chain_valid else 'Invalid'}")
        if r.certificate_expired:
            lines.append(f"  Expired:     Yes")
        if r.error:
            lines.append(f"  Error:       {r.error}")

        if r.signer:
            lines.append(f"  Signer:      {r.signer.full_name}")
            if r.signer.organization:
                lines.append(f"  Org:         {r.signer.organization}")
            if r.signer.serial_number:
                lines.append(f"  Serial No:   {r.signer.serial_number}")
            if r.signer.email:
                lines.append(f"  Email:       {r.signer.email}")
        lines.append("")

    return "\n".join(lines)


def format_results_json(results):
    """Format signature results as JSON."""
    output = []
    for r in results:
        entry = {
            "level": r.level,
            "valid": r.is_valid,
            "expired": r.certificate_expired,
            "chain_valid": r.certificate_chain_valid,
        }
        if r.error:
            entry["error"] = r.error
        if r.signer:
            entry["signer"] = _format_signer(r.signer)
        output.append(entry)
    return json.dumps(output, indent=2, ensure_ascii=False)


def format_results_terminal(results):
    """Format with ANSI colors for terminal output."""
    lines = []
    total = len(results)
    lines.append(f"Signatures found: {total}{' (nested)' if total > 1 else ''}")
    lines.append("")

    for r in results:
        if total > 1:
            lines.append(f"--- Level {r.level} ---")

        status = "\033[32mVALID\033[0m" if r.is_valid else "\033[31mINVALID\033[0m"
        lines.append(f"  Status:      {status}")
        lines.append(f"  Chain:       {'Valid' if r.certificate_chain_valid else 'Invalid'}")
        if r.certificate_expired:
            lines.append(f"  Expired:     \033[33mYes\033[0m")
        if r.error:
            lines.append(f"  Error:       {r.error}")

        if r.signer:
            lines.append(f"  Signer:      {r.signer.full_name}")
            if r.signer.organization:
                lines.append(f"  Org:         {r.signer.organization}")
            if r.signer.serial_number:
                lines.append(f"  Serial No:   {r.signer.serial_number}")
            if r.signer.email:
                lines.append(f"  Email:       {r.signer.email}")
        lines.append("")

    return "\n".join(lines)


def write_log(log_path, input_file, results, extracted_path=None):
    """Write signature info to a log file."""
    lines = []
    lines.append(f"unp7m - Signature Report")
    lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Input: {input_file}")
    if extracted_path:
        lines.append(f"Extracted: {extracted_path}")
    lines.append("")
    lines.append(format_results_text(results))
    log_path.write_text("\n".join(lines), encoding="utf-8")


def _write_error_log(input_file, error_msg):
    """Write error to log file next to input file (for GUI mode)."""
    try:
        p = Path(input_file)
        log_path = p.with_suffix(p.suffix + ".log")
        lines = [
            "unp7m - Error Report",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Input: {input_file}",
            "",
            f"ERROR: {error_msg}",
        ]
        log_path.write_text("\n".join(lines), encoding="utf-8")
    except Exception:
        pass


def process_file(file_path, output=None, no_extract=False, use_json=False,
                 ca_bundle=None, log_path=None, interactive=False):
    """Process a single .p7m file: verify signatures and extract content."""
    file_path = Path(file_path).resolve()

    if not file_path.exists():
        raise FileNotFoundError(f"file not found: {file_path}")

    sig_type = detect_signature_type(file_path)
    if sig_type != "CAdES":
        raise ValueError(f"{file_path} is not a .p7m file")

    if ca_bundle is None and interactive:
        print("Warning: ca-italiane.pem not found", file=sys.stderr)

    results = verify_cades_all_levels(file_path, ca_bundle)

    if not results:
        raise RuntimeError("could not parse signature")

    # Extract innermost content
    extracted_path = None
    if not no_extract:
        innermost_content = results[-1].content
        if innermost_content:
            extracted_path = Path(output) if output else get_extracted_filename(file_path)
            extracted_path.write_bytes(innermost_content)

    # Output signature info
    if interactive:
        if use_json:
            print(format_results_json(results))
        else:
            print(format_results_terminal(results))
        if extracted_path:
            print(f"Extracted: {extracted_path}")
    else:
        lp = Path(log_path) if log_path else file_path.with_suffix(file_path.suffix + ".log")
        write_log(lp, file_path, results, extracted_path)

    return all(r.is_valid for r in results)


# ============================================================================
# macOS Apple Events support (for "Open with" / double-click)
# ============================================================================

def _run_macos_gui(files_from_argv):
    """Run as macOS GUI app, handling Apple Events for file open."""
    ca_bundle = _DEFAULT_CA_BUNDLE
    processed = set()

    def _process(filepath):
        fp = str(filepath)
        if fp in processed:
            return
        processed.add(fp)
        try:
            process_file(fp, ca_bundle=ca_bundle, interactive=False)
        except Exception as e:
            _write_error_log(fp, str(e))

    # Process any files passed via argv (e.g. `open -a unp7m file.p7m`)
    for f in files_from_argv:
        _process(f)

    try:
        from Foundation import NSObject, NSAppleEventManager
        from AppKit import NSApplication, NSApp
        from PyObjCTools import AppHelper
        import objc

        class AppDelegate(NSObject):
            def applicationWillFinishLaunching_(self, notification):
                # Register for open document Apple Events
                em = NSAppleEventManager.sharedAppleEventManager()
                em.setEventHandler_andSelector_forEventClass_andEventID_(
                    self,
                    objc.selector(self.handleOpenEvent_withReply_, signature=b'v@:@@'),
                    int.from_bytes(b'aevt', 'big'),  # kCoreEventClass
                    int.from_bytes(b'odoc', 'big'),   # kAEOpenDocuments
                )

            def handleOpenEvent_withReply_(self, event, reply):
                # Extract file URLs from the Apple Event
                from Foundation import NSAppleEventDescriptor
                desc = event.paramDescriptorForKeyword_(int.from_bytes(b'----', 'big'))
                if desc is None:
                    NSApp.terminate_(None)
                    return

                count = desc.numberOfItems()
                if count == 0:
                    # Single item
                    url_str = desc.stringValue()
                    if url_str:
                        path = url_str.replace("file://", "")
                        from urllib.parse import unquote
                        _process(unquote(path))
                else:
                    from urllib.parse import unquote
                    for i in range(1, count + 1):
                        item = desc.descriptorAtIndex_(i)
                        url_str = item.stringValue()
                        if url_str:
                            path = url_str.replace("file://", "")
                            _process(unquote(path))

                NSApp.terminate_(None)

            def applicationDidFinishLaunching_(self, notification):
                # If we already processed files from argv and no Apple Events came, quit
                if processed:
                    # Give a tiny bit of time for any pending events
                    from Foundation import NSTimer
                    NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                        0.5, self, objc.selector(self.checkAndQuit_, signature=b'v@:@'), None, False
                    )
                else:
                    # Wait a bit for Apple Events
                    from Foundation import NSTimer
                    NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                        2.0, self, objc.selector(self.checkAndQuit_, signature=b'v@:@'), None, False
                    )

            def checkAndQuit_(self, timer):
                NSApp.terminate_(None)

        app = NSApplication.sharedApplication()
        delegate = AppDelegate.alloc().init()
        app.setDelegate_(delegate)
        AppHelper.runEventLoop()

    except ImportError:
        # PyObjC not available — just process argv files and exit
        if not processed:
            # No files at all
            pass


# ============================================================================
# CLI entry point
# ============================================================================

def main():
    interactive = _is_terminal()

    # If not interactive (GUI mode on macOS), handle Apple Events
    if not interactive:
        # Filter out macOS-injected args like -psn_*
        files = [a for a in sys.argv[1:] if not a.startswith('-psn')]
        _run_macos_gui(files)
        return

    # CLI mode: use argparse
    parser = argparse.ArgumentParser(
        prog="unp7m",
        description="Extract PDF from .p7m files and display signature information.",
    )
    parser.add_argument("file", type=Path, help="Input .p7m file")
    parser.add_argument("-o", "--output", type=Path, help="Output path for extracted file")
    parser.add_argument("--no-extract", action="store_true", help="Don't extract, only show signature info")
    parser.add_argument("--json", action="store_true", help="Output signature info as JSON")
    parser.add_argument("--ca-bundle", type=Path, help="Path to CA certificate bundle")
    parser.add_argument("--log", type=Path, help="Path for log file")

    args = parser.parse_args()
    ca_bundle = args.ca_bundle or _DEFAULT_CA_BUNDLE

    try:
        all_valid = process_file(
            args.file,
            output=args.output,
            no_extract=args.no_extract,
            use_json=args.json,
            ca_bundle=ca_bundle,
            log_path=args.log,
            interactive=True,
        )
        sys.exit(0 if all_valid else 1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
