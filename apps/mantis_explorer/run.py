"""Standalone launcher for Mantis Explorer on port 5005."""

from apps.mantis_explorer.app import create_app
from apps.mantis_explorer.data import SLUG_TO_ORG, get_report

if __name__ == "__main__":
    report = get_report("", "")
    print(f"Mantis Explorer: {len(SLUG_TO_ORG)} institutions, {len(report)} students")
    app = create_app()
    app.run(host="0.0.0.0", port=5005, debug=False, threaded=True)
