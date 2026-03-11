# AGENTS.md - PaCA Development Guide

This file provides guidelines for agentic coding agents working in the PaCA repository.

---

## Project Overview

PaCA (Project for Approximate Computing Analysis) is a Python framework for automated generation, simulation, analysis, and tracking of approximate computing variants for RISC-V architecture.

**Key Technologies:**
- Python 3.8+
- RISC-V toolchain (riscv32-unknown-elf-g++)
- Spike RISC-V simulator
- Prof5 energy profiler

---

## Build, Test, and Run Commands

### Installation

```bash
pip install -r requirements.txt
```

### Running Applications

```bash
# Brute force mode
python src/run.py --app fft --workers 4 --forcabruta

# Tree pruning mode
python src/run.py --app fft --workers 4 --arvorePoda --threshold 0.05 --alpha 0.5
```

Available apps: `fft`, `kmeans`, `sobel`, `blackscholes`, `inversek2j`, `jmeint`

### Running Tests

```bash
# Run all tests
pytest

# Run a single test file
pytest src/test_parser.py

# Run a single test function
pytest src/test_parser.py::test_function_name -v

# Run with verbose output
pytest -v
```

### Linting and Formatting

```bash
# Format code with Black
black src/

# Run pylint
pylint src/
```

### Docker Execution

```bash
# Pull pre-built container
docker pull gregoriokn/lscad_approx:v2

# Run container
docker run -it --rm -v $(pwd):/workspace -w /workspace gregoriokn/lscad_approx:v2 /bin/bash
```

---

## Code Style Guidelines

### General Principles

- Write clear, descriptive code prioritizing readability over cleverness
- Use English for all code, comments, and documentation
- Keep functions focused and reasonably sized (under 100 lines when possible)
- Add docstrings to all modules, classes, and public functions

### Imports

Organize imports in the following order, with a blank line between groups:

```python
# Standard library
import os
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import logging
import threading
import json

# Third-party packages
import numpy as np
import pandas as pd
import networkx as nx

# Local application modules
from config_base import BASE_CONFIG
from database.variant_tracker import add_executed_variant
from code_parser import parse_code
from utils.logger import setup_logging
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Modules | lowercase with underscores | `code_parser.py`, `variant_tracker.py` |
| Functions | snake_case | `parse_code()`, `generate_variants()` |
| Classes | PascalCase | `VariantStatusMonitor`, `TempFiles` |
| Constants | UPPER_SNAKE_CASE | `BASE_CONFIG`, `AVAILABLE_APPS`, `FFT_CONFIG` |
| Variables | snake_case | `modified_lines`, `variant_hash` |
| Private functions | prefix with underscore | `_internal_helper()` |

### Type Annotations

Use type hints for function parameters and return values:

```python
from typing import Tuple, List, Dict, Optional

def parse_code(file_path: str) -> Tuple[List[str], List[int], Dict[int, int]]:
    """Analyzes source code file to identify modifiable lines."""
    ...

def generate_variants(
    lines: List[str],
    modifiable_lines: List[int],
    physical_to_logical: dict,
    operation_map: dict,
    output_folder: str,
    file_name: str,
    executed_file: str = "executados.txt",
    limit: Optional[int] = None,
    strategy: str = "all"
) -> List[Tuple[str, str]]:
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def function_name(param1: str, param2: int) -> bool:
    """
    Short description of what the function does.

    Longer description if needed, explaining the behavior
    and any important edge cases.

    Args:
        param1: Description of first parameter.
        param2: Description of second parameter.

    Returns:
        Description of what the function returns.

    Raises:
        ValueError: When this specific error can occur.
        FileNotFoundError: When input file doesn't exist.
    """
```

### Configuration

Application-specific configurations use uppercase dictionaries:

```python
FFT_CONFIG = {
    "app_name": "fft",
    "input_file_for_variants": "data/applications/fft/src/fourier.cpp",
    "operations_map": {'*': 'FMULX', '+': 'FADDX', '-': 'FSUBX'},
    "train_data_input": "512",
    "optimization_level": "-O"
}
```

### Error Handling

- Use try/except blocks for operations that may fail (file I/O, subprocess calls)
- Log errors with appropriate severity before re-raising or handling
- Provide informative error messages including context

```python
try:
    with open(file_path, 'r') as f:
        lines = f.readlines()
except FileNotFoundError:
    logging.error(f"File not found: {file_path}")
    return [], [], {}
except PermissionError:
    logging.error(f"Permission denied: {file_path}")
    raise
```

### Logging

- Use the `logging` module for runtime diagnostics
- Configure logging via `utils.logger.setup_logging()`
- Log levels: DEBUG (detailed info), INFO (expected events), WARNING (unexpected but handled), ERROR (failures)

```python
import logging

logger = logging.getLogger(__name__)

logger.info("Starting variant generation")
logger.warning(f"No modifiable lines found in: {file_path}")
logger.error(f"Compilation failed: {error}")
```

### File Paths

- Use relative paths from project root for configuration
- Use `os.path.join()` for path construction
- Define paths in configuration dictionaries

### Concurrency

- Use `ThreadPoolExecutor` for parallel variant processing
- Pass configuration to worker threads, don't rely on global state
- Use thread-safe data structures when needed

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

with ThreadPoolExecutor(max_workers=workers) as executor:
    futures = {executor.submit(simulate_variant, v, cfg): v for v in variants}
    for future in as_completed(futures):
        result = future.result()
```

### Code Organization

```
src/
├── apps/              # Application-specific modules (fft.py, kmeans.py, etc.)
├── database/          # Variant tracking database
├── execution/         # Compilation and simulation
├── utils/             # Utility modules (logger, file_utils, etc.)
├── code_parser.py     # Source code parser
├── config.py          # Application configuration
├── config_base.py     # Base configuration
├── generator.py       # Variant generator
├── run.py             # Main execution script
└── transformations.py # Code transformations
```

---

## Adding New Applications

1. Create module in `src/apps/myapp.py` with:
   - `MYAPP_CONFIG` dictionary with required keys
   - `cleanup_variant_files()` function
   - `prepare_environment()`, `generate_variants()`, `find_variants_to_simulate()`, `simulate_variant()` functions

2. Register in `src/run.py`:
   ```python
   AVAILABLE_APPS = {
       "myapp": "apps.myapp",
   }
   ```

3. Add source code to `data/applications/myapp/src/`

4. Use `//anotacao:` comments to mark approximable lines

---

## Common Patterns

### Application Module Structure

```python
"""
Module docstring explaining the application purpose.
"""

import os
import logging
from code_parser import parse_code

MYAPP_CONFIG = {
    "app_name": "myapp",
    "input_file_for_variants": "data/applications/myapp/src/main.cpp",
    "operations_map": {'*': 'FMULX', '+': 'FADDX'},
    # ... other config
}

def cleanup_variant_files(variant_hash, config, preserve_logs=True):
    """Remove temporary files while preserving results."""
    ...

def prepare_environment(base_config):
    """Prepare execution environment."""
    ...

def generate_variants(base_config):
    """Generate all variants for this application."""
    ...

def find_variants_to_simulate(base_config):
    """Return list of variants to simulate."""
    ...

def simulate_variant(variant_file, variant_hash, base_config, status_monitor):
    """Simulate a single variant."""
    ...
```

### Subprocess Execution

```python
import subprocess

result = subprocess.run(
    ["riscv32-unknown-elf-g++", "-o", output, source],
    capture_output=True,
    text=True,
    timeout=60
)

if result.returncode != 0:
    logging.error(f"Compilation failed: {result.stderr}")
    raise RuntimeError(f"Compilation failed: {result.stderr}")
```

---

## Testing Guidelines

- Tests should be placed in `src/` alongside the code they test
- Use descriptive test function names: `test_<what_is_being_tested>`
- Use pytest fixtures for common setup
- Assert specific conditions, not just "no exception"

```python
def test_parse_code_finds_annotations():
    """Test that parser correctly identifies annotated lines."""
    code = """//anotacao:
float x = a + b;"""
    
    lines, modifiable_lines, mapping = parse_code_string(code)
    
    assert len(modifiable_lines) == 1
    assert modifiable_lines[0] == 1  # Second line (0-indexed: 1)
```

---

## Notes

- This project uses a mix of English (code) and Portuguese (comments, some outputs)
- The RISC-V toolchain and Spike simulator are external dependencies
- Results are stored in `storage/` directory
- Use checkpoints for long-running executions
