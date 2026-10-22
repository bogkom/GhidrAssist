"""No network needed; tests the packaged RAG CPU32 downloader with synthetic PDFs."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

SOURCE = (Path(__file__).resolve().parents[1] /
          "src/main/resources/rag_cpu32_downloader.py")
SPEC = importlib.util.spec_from_file_location("rag_cpu32_downloader", SOURCE)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)
PDF = b"%PDF-1.4\n" + b"%synthetic test only\n" + b"%%EOF\n"


class ManualDownloaderTests(unittest.TestCase):
    def test_direct_catalog_links_and_names(self):
        md = """
| MC68332UM.pdf | [Manual](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf) |
| MC68331UM.pdf | [Product](https://www.nxp.com/products/MC68331) |
| MC68336376UM05.pdf | [SIM](https://www.nxp.com/docs/en/user-guide/MC68336376UM05.pdf) |
| MC68336376UM13.pdf | [TouCAN](https://www.nxp.com/docs/en/user-guide/MC68336376UM13.pdf) |
| [Offsite](https://evil.invalid/MC68332UM.pdf) |
| [Dup](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf) |
"""
        result = mod.direct_catalog_urls(md)
        self.assertEqual([doc for doc, url in result], [
            "MC68332UM", "MC68336376UM05", "MC68336376UM13"
        ])
        self.assertEqual(mod.ALIASES["MC68336376UM13"][0], "MC68376-only")
        self.assertEqual(mod.ALIASES["MC68336376UM05"][1],
                         "MC68336_68376_05_SIM.pdf")

    def test_pdf_validation_and_atomic_conflict(self):
        with tempfile.TemporaryDirectory() as t:
            dest = Path(t)
            self.assertTrue(mod.pdf_ok(PDF))
            self.assertFalse(mod.pdf_ok(b"<html>Sign in to NXP</html>"))
            rows = []
            mod.store_pdf(dest, "MC68332UM", PDF, "test", rows, "UNVERIFIED")
            mod.store_pdf(dest, "MC68332UM", PDF, "test", rows, "UNVERIFIED")
            mod.store_pdf(dest, "MC68332UM",
                          PDF.replace(b"test", b"different"), "test", rows,
                          "UNVERIFIED")
            self.assertEqual([r["status"] for r in rows],
                             ["SAVED", "ALREADY_PRESENT", "CONFLICT_NOT_OVERWRITTEN"])
            self.assertEqual((dest / "MC68332/MC68332UM.pdf").read_bytes(), PDF)

    def test_zip_known_archive_and_zip_slip(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            archive = root / "MC683336_376UM_ZIP.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("../c5sim.pdf", PDF)
                z.writestr("sections/c8qadc.pdf", PDF)
                z.writestr("appendix/apdreg.pdf", PDF)
                z.writestr("../../../evil.pdf", PDF)
                z.writestr("sections/c5sim.pdf", PDF)
            rows = []
            mod.extract_zip(archive, root / "out", rows)
            self.assertTrue((root / "out/MC68336-376/MC68336_68376_05_SIM.pdf").exists())
            self.assertTrue((root / "out/MC68336-376/MC68336_68376_08_QADC.pdf").exists())
            self.assertTrue((root / "out/MC68336-376/MC68336_68376_D_REGISTERS.pdf").exists())
            self.assertFalse((root / "evil.pdf").exists())
            self.assertEqual(
                sum(r.get("status") == "DUPLICATE_ARCHIVE_ENTRY_SKIPPED" for r in rows), 1
            )

    def test_zip_wrong_device_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            archive = Path(t) / "MC68332_MODULES.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("c5sim.pdf", PDF)
            with self.assertRaises(ValueError):
                mod.extract_zip(archive, Path(t)/"out", [])

    def test_offline_and_dry_run(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            archive = root / "MC683336_376UM_ZIP.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("c5sim.pdf", PDF)
            out = root / "download"
            self.assertEqual(mod.main(["--offline", "--zip", str(archive),
                                       "--output", str(out)]), 0)
            report = json.loads((out/"download_report.json").read_text())
            self.assertEqual(report["documents"][0]["status"], "SAVED")
            self.assertEqual(mod.main(["--offline", "--zip", str(archive),
                                       "--output", str(out)]), 0)
            self.assertEqual(mod.main(["--offline", "--zip", str(archive),
                                       "--output", str(out), "--dry-run"]), 0)


if __name__ == "__main__":
    unittest.main()
