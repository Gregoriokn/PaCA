"""
Error Analysis Module for PaCA

This module provides comprehensive error analysis between reference (exact)
and approximate variant outputs. It calculates various error metrics including
MSE, MAE, MRE (Mean Relative Error), and derived accuracy metrics.

The module handles multiple input formats (JSON, plain text) and provides
safe fallback mechanisms for edge cases.

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

import warnings
import math
import json
import logging
from pathlib import Path
from typing import Iterable, List, Any, Optional, Dict


def safe_correlation(x: Any, y: Any) -> Optional[float]:
    """
    Calculates Pearson correlation coefficient with error handling.
    
    Provides a simple fallback implementation when scipy/numpy are unavailable.
    
    Args:
        x: First data sequence
        y: Second data sequence
        
    Returns:
        float: Correlation coefficient in [-1, 1], or None on failure
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            x_seq = _ensure_sequence(x)
            y_seq = _ensure_sequence(y)
            n = min(len(x_seq), len(y_seq))
            if n == 0:
                return None
            x_vals = [float(v) for v in x_seq[:n]]
            y_vals = [float(v) for v in y_seq[:n]]
            mean_x = sum(x_vals) / n
            mean_y = sum(y_vals) / n
            num = sum((a - mean_x) * (b - mean_y) for a, b in zip(x_vals, y_vals))
            den_x = math.sqrt(sum((a - mean_x) ** 2 for a in x_vals))
            den_y = math.sqrt(sum((b - mean_y) ** 2 for b in y_vals))
            denom = den_x * den_y
            if denom == 0:
                return None
            return num / denom
        except Exception:
            logging.exception("safe_correlation failed")
            return None


def _ensure_sequence(data: Any) -> List[Any]:
    """
    Ensures that input data is converted to a list of elements.
    
    Handles various input types including strings, tuples, generators, etc.
    
    Args:
        data: Input data of various types
        
    Returns:
        List of elements
    """
    if data is None:
        return []
    if isinstance(data, (list, tuple)):
        return list(data)
    # Strings: keep as single line (don't split into chars)
    if isinstance(data, str):
        return [data]
    try:
        # Detect object with __len__
        if hasattr(data, '__len__'):
            return list(data)
    except Exception:
        pass
    # Iterables (generators, map, etc.)
    try:
        return list(data)
    except Exception:
        # Scalar value
        return [data]


def calculate_metrics(exact_data: Iterable[float], approx_data: Iterable[float]) -> Dict[str, float]:
    """
    Calculates elementary error metrics between exact and approximate data.
    
    Metrics computed:
    - count: Number of data points compared
    - mse: Mean Squared Error
    - mae: Mean Absolute Error
    - max_error: Maximum absolute error
    - mare: Mean Absolute Relative Error
    - accuracy: 1 - MARE (truncated to [0, 1])
    
    Args:
        exact_data: Reference/ground truth values
        approx_data: Approximate/variant values
        
    Returns:
        Dictionary with all computed metrics
    """
    exact_seq = _ensure_sequence(exact_data)
    approx_seq = _ensure_sequence(approx_data)
    n = min(len(exact_seq), len(approx_seq))
    if n == 0:
        return {"count": 0, "mse": 0.0, "mae": 0.0, "max_error": 0.0, "mare": None, "accuracy": 0.0}

    sum_sq = 0.0
    sum_abs = 0.0
    sum_rel = 0.0
    max_err = 0.0
    eps = 1e-12

    for a_raw, b_raw in zip(exact_seq[:n], approx_seq[:n]):
        try:
            a = float(a_raw)
            b = float(b_raw)
        except Exception:
            # Skip non-convertible pairs
            n -= 1
            continue
        diff = b - a
        absdiff = abs(diff)
        sum_sq += diff * diff
        sum_abs += absdiff
        denom = abs(a) + eps
        sum_rel += absdiff / denom
        if absdiff > max_err:
            max_err = absdiff

    if n <= 0:
        return {"count": 0, "mse": 0.0, "mae": 0.0, "max_error": 0.0, "mare": None, "accuracy": 0.0}

    mse = sum_sq / n
    mae = sum_abs / n
    mare = sum_rel / n  # mean absolute relative error
    # Simple accuracy definition: 1 - MARE, truncated to [0,1]
    accuracy = max(0.0, 1.0 - mare)

    return {
        "count": n,
        "mse": mse,
        "mae": mae,
        "max_error": max_err,
        "mare": mare,
        "accuracy": accuracy
    }


def calculate_error(output_path: str, reference_path: str) -> Dict[str, float]:
    """
    Main entry point for error calculation.
    
    Reads output and reference files (text or JSON format), extracts numeric
    sequences, computes metrics, and saves results alongside output file.
    
    Args:
        output_path: Path to variant output file
        reference_path: Path to reference/exact output file
        
    Returns:
        Dictionary with computed error metrics
    """
    outp = Path(output_path)
    refp = Path(reference_path)
    logging.info(f"[error_analyzer] calculate_error called with output={outp} reference={refp}")

    if not outp.exists():
        logging.warning(f"[error_analyzer] output file not found: {outp}")
        return {"count": 0, "mse": 0.0, "mae": 0.0, "max_error": 0.0, "mare": None, "accuracy": 0.0}
    if not refp.exists():
        logging.warning(f"[error_analyzer] reference file not found: {refp}")
        return {"count": 0, "mse": 0.0, "mae": 0.0, "max_error": 0.0, "mare": None, "accuracy": 0.0}

    def _read_numbers(p: Path) -> List[float]:
        """
        Reads numeric data from file, trying multiple formats.
        
        Attempts JSON first, then falls back to regex extraction.
        """
        try:
            text = p.read_text(encoding='utf-8')
        except Exception:
            try:
                text = p.read_text(encoding='latin-1')
            except Exception:
                logging.exception(f"[error_analyzer] failed to read {p}")
                return []

        # Try JSON first
        try:
            data = json.loads(text)
            # Accept nested lists, dictionaries with numeric values, etc.
            if isinstance(data, list):
                # Flatten recursively and extract numbers
                nums = []
                def _flatten(obj):
                    if isinstance(obj, (list, tuple)):
                        for it in obj:
                            _flatten(it)
                    elif isinstance(obj, dict):
                        for v in obj.values():
                            _flatten(v)
                    else:
                        try:
                            nums.append(float(obj))
                        except Exception:
                            pass
                _flatten(data)
                return nums
            elif isinstance(data, dict):
                # Extract values
                nums = []
                for v in data.values():
                    try:
                        nums.append(float(v))
                    except Exception:
                        pass
                return nums
            else:
                # Scalar value
                try:
                    return [float(data)]
                except Exception:
                    return []
        except Exception:
            pass

        # Fallback: regex extraction from plain text
        parts = []
        for line in text.splitlines():
            for token in line.strip().split():
                try:
                    parts.append(float(token))
                except Exception:
                    # Try removing commas/pointers like "1,234" or "1.234,"
                    tok = token.strip().strip(' ,;')
                    try:
                        parts.append(float(tok))
                    except Exception:
                        continue
        return parts

    ref_nums = _read_numbers(refp)
    out_nums = _read_numbers(outp)

    metrics = calculate_metrics(ref_nums, out_nums)

    # Save metrics alongside output file for auditing
    try:
        metrics_path = outp.with_suffix(outp.suffix + ".error.json")
        metrics_path.write_text(json.dumps(metrics, indent=2), encoding='utf-8')
        logging.info(f"[error_analyzer] metrics saved to {metrics_path}")
    except Exception:
        logging.exception("[error_analyzer] failed to save metrics")

    return metrics
