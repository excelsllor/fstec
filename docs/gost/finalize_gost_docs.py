from pathlib import Path
import os
import socket
import subprocess
import tempfile
import time

import uno
from com.sun.star.beans import PropertyValue

ROOT = Path(__file__).resolve().parents[2]
DOC_DIR = next(p.parent for p in (ROOT / "docs").glob("*/*.docx")
               if p.name.startswith("00_"))
SOFFICE = Path(r"C:\Program Files\LibreOffice\program\soffice.exe")


def prop(name, value):
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, timeout=45):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.5)
    return False


def update_and_export(desktop, path):
    if (path.parent / f".~lock.{path.name}#").exists():
        print("SKIP locked:", path.name)
        return
    source_url = uno.systemPathToFileUrl(str(path))
    doc = desktop.loadComponentFromURL(
        source_url, "_blank", 0,
        (prop("Hidden", True), prop("ReadOnly", False)))
    if doc is None:
        print("SKIP locked:", path.name)
        return
    tmp_holder = None
    try:
        doc.refresh()
        indexes = doc.getDocumentIndexes()
        for i in range(indexes.getCount()):
            indexes.getByIndex(i).update()
        doc.refresh()

        tmp_holder = tempfile.TemporaryDirectory(prefix="gost_docx_")
        tmp_docx = Path(tmp_holder.name) / path.name
        doc.storeToURL(
            uno.systemPathToFileUrl(str(tmp_docx)),
            (prop("FilterName", "MS Word 2007 XML"), prop("Overwrite", True)))

        pdf_path = path.with_suffix(".pdf")
        doc.storeToURL(
            uno.systemPathToFileUrl(str(pdf_path)),
            (prop("FilterName", "writer_pdf_Export"), prop("Overwrite", True)))
        doc.close(True)
        try:
            os.replace(tmp_docx, path)
        except PermissionError:
            print("SKIP locked after export:", path.name)
            return
        print("finalized", path.name, "->", pdf_path.name)
    finally:
        try:
            doc.close(True)
        except Exception:
            pass
        if tmp_holder is not None:
            tmp_holder.cleanup()


def main():
    files = sorted(
        p for p in DOC_DIR.glob("*.docx")
        if not p.name.startswith("~$") and ".pre_security" not in p.name
    )
    if not files:
        raise SystemExit("No DOCX files found")

    port = free_port()
    with tempfile.TemporaryDirectory(
            prefix="gost_profile_", ignore_cleanup_errors=True) as profile:
        profile_url = uno.systemPathToFileUrl(profile)
        proc = subprocess.Popen([
            str(SOFFICE), "--headless", "--norestore", "--nologo",
            "--nodefault", "--nofirststartwizard",
            f"--accept=socket,host=127.0.0.1,port={port};urp;",
            f"-env:UserInstallation={profile_url}",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not wait_port(port):
                raise RuntimeError("LibreOffice did not open the UNO socket")
            local = uno.getComponentContext()
            resolver = local.ServiceManager.createInstanceWithContext(
                "com.sun.star.bridge.UnoUrlResolver", local)
            ctx = resolver.resolve(
                f"uno:socket,host=127.0.0.1,port={port};urp;StarOffice.ComponentContext")
            desktop = ctx.ServiceManager.createInstanceWithContext(
                "com.sun.star.frame.Desktop", ctx)
            for path in files:
                update_and_export(desktop, path)
        finally:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False)
                proc.wait(timeout=15)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
