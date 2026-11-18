from pathlib import Path

from streamlit.testing.v1 import AppTest

APP_FILE = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"


def test_dashboard_runs_without_error():
    app = AppTest.from_file(str(APP_FILE), default_timeout=30)
    app.run()
    assert not app.exception
    assert len(app.tabs) == 4