import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _run_in_tmp_dir(tmp_path, monkeypatch):
    """Tests write vaults and outputs to the working directory; keep them out of the repo."""
    monkeypatch.chdir(tmp_path)
