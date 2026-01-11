from __future__ import annotations
import argparse
from config import COMMON_DEFAULTS

def add_common_args(ap: argparse.ArgumentParser) -> argparse.ArgumentParser:
    ap.add_argument("--data-dir", default=COMMON_DEFAULTS["data_dir"])
    ap.add_argument("--pattern", default=COMMON_DEFAULTS["pattern"])
    ap.add_argument("--label-col", default=COMMON_DEFAULTS["label_col"])
    ap.add_argument("--chunksize", type=int, default=COMMON_DEFAULTS["chunksize"])

    ap.add_argument("--max-rows", type=int, default=COMMON_DEFAULTS["max_rows"])
    ap.add_argument("--per-chunk-sample", type=float, default=COMMON_DEFAULTS["per_chunk_sample"])
    ap.add_argument("--random-state", type=int, default=COMMON_DEFAULTS["random_state"])
    ap.add_argument("--rows-per-file", type=int, default=COMMON_DEFAULTS["rows_per_file"])
    
    return ap
