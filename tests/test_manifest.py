import tempfile
from pathlib import Path
from unittest import TestCase

from toolkit.manifest import load_merge_request


class ManifestTest(TestCase):
    def test_loads_merge_request_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mr.json"
            path.write_text(
                '{"iid":"42","title":"MR","author":"sergey","files":[{"path":"main.tf","content":"resource"}]}',
                encoding="utf-8",
            )

            mr = load_merge_request(path)

        self.assertEqual(mr.iid, "42")
        self.assertEqual(mr.files[0].path, "main.tf")
