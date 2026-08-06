import sys
from pathlib import Path

API_DIR = Path(__file__).resolve().parents[1]
PACKAGES_DIR = API_DIR.parents[1] / "packages" / "event-contracts"

for p in (str(API_DIR), str(PACKAGES_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)
