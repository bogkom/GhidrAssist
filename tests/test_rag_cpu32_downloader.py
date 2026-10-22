"""No network needed; tests the packaged RAG CPU32 downloader with synthetic PDFs."""
import importlib.util
import json
from unittest.mock import patch
from urllib.error import HTTPError
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
                z.writestr("first/c5sim.pdf", PDF)
                z.writestr("sections/c8qadc.pdf", PDF)
                z.writestr("appendix/apdreg.pdf", PDF)
                z.writestr("../../../evil.pdf", PDF)
                z.writestr("sections/c5sim.pdf", PDF)
                z.writestr("c4cpu.pdf", PDF)
            rows = []
            mod.extract_zip(archive, root / "out", rows)
            self.assertTrue((root / "out/MC68336-376/MC68336_68376_05_SIM.pdf").exists())
            self.assertTrue((root / "out/MC68336-376/MC68336_68376_08_QADC.pdf").exists())
            self.assertTrue((root / "out/MC68336-376/MC68336_68376_D_REGISTERS.pdf").exists())
            self.assertFalse((root / "evil.pdf").exists())
            self.assertTrue((root / "out/TO_REVIEW/MC68336_68376_UNMAPPED_c4cpu.pdf").exists())
            self.assertEqual(sum(r.get("status") == "SKIPPED_UNSAFE_ZIP_PATH"
                                 for r in rows), 1)
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

    def test_import_local_pdf_folder_with_scoped_and_unverified_names(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            source = root / "input"
            source.mkdir()
            (source / "MC331_SIM.pdf").write_bytes(PDF)
            (source / "MC68336_68376_05_SIM.pdf").write_bytes(PDF)
            (source / "c5sim.pdf").write_bytes(PDF)
            (source / "not_a_pdf.pdf").write_bytes(b"<html>fake</html>")
            dest = root / "output"
            # Three valid PDFs are saved; the fake HTML is rejected and
            # reported, so the overall code is partial success (1).
            self.assertEqual(mod.main(["--offline", "--pdf-dir", str(source),
                                       "--output", str(dest)]), 1)
            self.assertTrue((dest / "MC68331/MC68331_SIM.pdf").exists())
            self.assertTrue((dest / "MC68336-376/MC68336_68376_05_SIM.pdf").exists())
            self.assertTrue((dest / "TO_REVIEW/UNVERIFIED_c5sim.pdf").exists())
            report = json.loads((dest / "download_report.json").read_text())
            self.assertTrue(any(d.get("status") == "INVALID_PDF" for d in report["documents"]))
            self.assertEqual(mod.classify_local_pdf("c5sim.pdf")[0], "TO_REVIEW")
            self.assertEqual(mod.classify_local_pdf("MC68336_68376_13_TOUCAN.pdf")[0],
                             "MC68376-only")

    def test_nxp_repeated_404_stops_further_download_attempts(self):
        sample = "\\n".join(
            "[x](https://www.nxp.com/docs/en/user-guide/" + name + ".pdf)"
            for name in ["MC68332UM", "MC68336376UM05", "MC68336376UM08"]
        )
        with tempfile.TemporaryDirectory() as t:
            with (
                patch.object(mod, "read_catalog", return_value=sample),
                patch.object(mod, "fetch_pdf", side_effect=lambda url:
                    (_ for _ in ()).throw(HTTPError(url, 404, "Not Found", None, None))
                ) as mock_download
            ):
                self.assertEqual(mod.main(["--output", t]), 2)
                self.assertEqual(mock_download.call_count, 2)
            report = json.loads((Path(t) / "download_report.json").read_text())
            self.assertTrue(any(
                d.get("status") == "SKIPPED_NXP_DIRECT_ENDPOINT_UNAVAILABLE"
                for d in report["documents"]
            ))

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
