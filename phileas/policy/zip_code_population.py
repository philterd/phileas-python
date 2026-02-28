from __future__ import annotations

import csv
import os
from typing import Dict, Optional

_population_map: Optional[Dict[str, int]] = None

_CSV_PATH = os.path.join(os.path.dirname(__file__), "..", "resources", "zip-code-population.csv")


def _load_population_map() -> Dict[str, int]:
    """Load the zip-code → population mapping from the bundled CSV file."""
    csv_path = os.path.normpath(_CSV_PATH)
    try:
        f_handle = open(csv_path, encoding="utf-8", newline="")
    except OSError as exc:
        raise OSError(
            f"zip-code-population.csv not found at {csv_path!r}. "
            "Ensure the phileas package resources are installed correctly."
        ) from exc
    result: Dict[str, int] = {}
    with f_handle as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) >= 2:
                zip_code = row[0].strip()
                try:
                    result[zip_code] = int(row[1].strip())
                except ValueError:
                    pass
    return result


def get_population(zip_code: str) -> Optional[int]:
    """Return the population for the given 5-digit zip code, or None if not found."""
    global _population_map
    if _population_map is None:
        _population_map = _load_population_map()
    # For 5+4 zip codes (e.g. "12345-6789") use the 5-digit prefix
    if "-" in zip_code:
        zip_code = zip_code.split("-")[0]
    return _population_map.get(zip_code)
