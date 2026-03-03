# PaCA: Project for Approximate Computing Analysis

A comprehensive framework for automated generation, simulation, analysis, and tracking of approximate computing variants, with support for scientific applications, RISC-V toolchain integration, Prof5 profiler, error analysis, and parallel execution.

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Academic-red.svg)](LICENSE)
[![RISC-V](https://img.shields.io/badge/RISC-V-Spike-green.svg)](https://github.com/riscv-software-src/riscv-isa-sim)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Docker (Recommended)](#docker-recommended)
  - [Manual Installation](#manual-installation)
- [Usage](#usage)
  - [Running Applications](#running-applications)
  - [Execution Modes](#execution-modes)
    - [Brute Force Mode](#brute-force-mode)
    - [Tree Pruning Mode](#tree-pruning-mode)
  - [Command Line Options](#command-line-options)
- [Project Structure](#project-structure)
- [Adding New Applications](#adding-new-applications)
- [Analyzing Results](#analyzing-results)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

PaCA (Approximate Computing Analysis Project) automates the generation of approximate code variants, compiles them for RISC-V architecture, simulates execution via Spike, analyzes performance and accuracy through Prof5 profiler, and tracks variants throughout the experimental workflow.

**Approximate Computing** is an emerging paradigm that trades computational precision for energy efficiency by using hardware approximations. This framework helps researchers and developers explore the design space of approximate implementations.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          PaCA Framework                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │
│  │   Code       │───▶│  Generator   │───▶│   Variant    │           │
│  │   Parser     │    │              │    │   Storage    │           │
│  └──────────────┘    └──────────────┘    └──────────────┘           │
│         │                   │                   │                   │
│         ▼                   ▼                   ▼                   │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │                    Execution Pipeline                    │       │
│  │  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   │       │
│  │  │ Compile │──▶│  Spike  │──▶│  Prof5  │──▶│  Error  │   │       │
│  │  │ (RISC-V)│   │ (Sim)   │   │ (Energy)│   │Analysis│    │       │
│  │  └─────────┘   └─────────┘   └─────────┘   └─────────┘   │       │
│  └──────────────────────────────────────────────────────────┘       │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │
│  │   Variant    │    │    Tree      │    │   Results    │           │
│  │   Tracker    │    │   Pruning    │    │   Storage    │           │
│  └──────────────┘    └──────────────┘    └──────────────┘           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Features

- **Automatic Variant Generation**: Generate multiple code variants using approximate operators (FADDX, FMULX, FSUBX)
- **Cross-Compilation**: Compile variants for RISC-V architecture using riscv32-unknown-elf-g++
- **Simulation**: Execute variants in the Spike RISC-V simulator
- **Performance Profiling**: Analyze energy consumption using Prof5 profiler
- **Error Analysis**: Compare variant outputs with reference to measure accuracy degradation
- **Variant Tracking**: Track executed variants, failures, and checkpoints for resumability
- **Tree Pruning**: Intelligent pruning of redundant variants using heuristic cost functions
- **Supported Applications**: FFT, K-Means, Sobel Edge Detection, Black-Scholes, Inverse Kinematics, JMEINT
- **Parallel Execution**: Multi-threaded variant processing
- **Comprehensive Logging**: Detailed logs and organized results storage

---

## Quick Start

### Running with Docker (Recommended)

```bash
# Pull and run the pre-built Docker container
docker pull gregoriokn/lscad_approx:v2
docker run -it --rm -v $(pwd):/workspace -w /workspace gregoriokn/lscad_approx:v2 /bin/bash

# Run FFT application in brute force mode
python src/run.py --app fft --workers 4 --forcabruta

# Run with tree pruning mode
python src/run.py --app fft --workers 4 --arvorePoda --threshold 0.05 --alpha 0.5
```

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run application
python src/run.py --app kmeans --workers 4 --forcabruta
```

---

## Installation

### Docker (Recommended)

The easiest way to run PaCA is using the pre-configured Docker container:

```bash
docker pull gregoriokn/lscad_approx:v2
docker run -it --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  gregoriokn/lscad_approx:v2 /bin/bash
```

The container includes:
- RISC-V toolchain (riscv32-unknown-elf-g++)
- Spike RISC-V simulator
- Python 3.8+ with all dependencies
- Pre-compiled approximate instruction set

---

## Docker Orchestration (Remote Execution)

PaCA supports running simulations **entirely from your host machine** while executing inside a Docker container. This is useful when you want to:
- Run from your local IDE
- Automatically sync code changes (annotations)
- Get results back to your host

### Setup

1. **Install Docker SDK on host:**
```bash
pip install docker
```

2. **Configure container ID in `src/config_base.py`:**
```python
# src/config_base.py
BASE_CONFIG = {
    ...
    "docker_container_id": "YOUR_CONTAINER_ID",
    "sync_from_container_after_run": True,  # Copy results back Running Remote
}
```

### Simulations

```bash
# FFT with auto-detected workers
python src/run.py --app fft --forcabruta

# FFT with specific workers
python src/run.py --app fft --workers 4 --forcabruta

# Tree pruning mode
python src/run.py --app fft --arvorePoda --threshold 0.05 --alpha 0.5

# All apps work: fft, kmeans, sobel, blackscholes, inversek2j, jmeint
```

### How It Works

1. **Connect** to container via Docker API
2. **Sync** project files (always fresh - reflects annotation changes)
3. **Execute** simulation inside container
4. **Copy** results back to host

### Manual Override

You can also specify container at runtime:
```bash
python src/run.py --app fft --container 3d04... --forcabruta
```

### Notes

- The system auto-detects optimal worker count based on container CPU/memory
- Files are always synced before execution (annotation changes are reflected)
- Results are automatically copied to `storage/executions/`

### Manual Installation

#### Prerequisites

- Python 3.8 or higher
- RISC-V toolchain (riscv32-unknown-elf-g++, riscv32-unknown-elf-objdump)
- Spike RISC-V simulator
- Linux/macOS (or WSL on Windows)

#### Python Dependencies

```bash
pip install -r requirements.txt
```

#### Configuration

Configure paths in `src/config_base.py` and `src/config.py` according to your environment:

```python
# src/config_base.py
BASE_CONFIG = {
    "executables_dir": "storage/executable",
    "outputs_dir": "storage/output",
    "logs_dir": "storage/logs",
    # ... other paths
}
```

---

## Usage

### Running Applications

Run a supported application with the following command:

```bash
python src/run.py --app [application_name] --workers [num_threads] --[execution_mode]
```

#### Available Applications

| Application | Description |
|-------------|-------------|
| `fft` | Fast Fourier Transform |
| `kmeans` | K-Means Clustering |
| `sobel` | Sobel Edge Detection |
| `blackscholes` | Black-Scholes Option Pricing |
| `inversek2j` | Inverse Kinematics (2D) |
| `jmeint` | Triangle-Triangle Intersection |

### Execution Modes

PaCA supports two execution modes:

#### Brute Force Mode

Explores all possible variant combinations:

```bash
python src/run.py --app fft --workers 4 --forcabruta
```

#### Tree Pruning Mode

Intelligently prunes variants using heuristic cost functions:

```bash
python src/run.py --app fft --workers 4 --arvorePoda --threshold 0.05 --alpha 0.5
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--app` | Application name (fft, kmeans, sobel, blackscholes, inversek2j, jmeint) | Required |
| `--workers` | Number of parallel workers (0 = CPU count - 1) | 0 |
| `--threshold` | Maximum cost threshold for pruning (tree mode) | 0.05 |
| `--alpha` | Error weight in heuristic (0.0-1.0). Energy weight = (1-alpha) | 1.0 |
| `--forcabruta` | Run in brute force mode | Required |
| `--arvorePoda` | Run in tree pruning mode | Required |

---

## Project Structure

```
PaCA/
├── src/
│   ├── apps/                     # Application-specific modules
│   │   ├── fft.py               # FFT application
│   │   ├── kmeans.py            # K-Means application
│   │   ├── sobel.py             # Sobel edge detection
│   │   ├── blackscholes.py      # Black-Scholes pricing
│   │   ├── inversek2j.py        # Inverse kinematics
│   │   └── jmeint.py            # Triangle intersection
│   │
│   ├── database/                 # Variant tracking database
│   │   └── variant_tracker.py   # Track executed/failed variants
│   │
│   ├── execution/                # Compilation and simulation
│   │   ├── compilation.py        # RISC-V compilation
│   │   └── simulation.py        # Spike simulation & Prof5
│   │
│   ├── utils/                    # Utility modules
│   │   ├── error_analyzer.py    # Error metrics calculation
│   │   ├── file_utils.py        # File operations
│   │   ├── pruning_tree.py      # Tree-based pruning
│   │   ├── logger.py            # Logging utilities
│   │   └── prof5fake.py         # Prof5 profiler wrapper
│   │
│   ├── code_parser.py           # Source code parser
│   ├── config.py                # Application configuration
│   ├── config_base.py           # Base configuration
│   ├── generator.py             # Variant generator
│   ├── gera_variantes.py        # Variant generation CLI
│   ├── hash_utils.py            # Hash generation utilities
│   ├── run.py                   # Main execution script
│   ├── test_parser.py           # Parser tests
│   └── transformations.py       # Code transformations
│
├── data/
│   ├── applications/             # Application source code
│   │   ├── fft/
│   │   ├── kmeans/
│   │   ├── sobel/
│   │   ├── blackscholes/
│   │   ├── inversek2j/
│   │   └── jmeint/
│   │
│   └── reference/               # Reference approximate functions
│       └── approx.h             # Approximate operator macros
│
├── storage/                      # Runtime storage (generated)
│   ├── executable/              # Compiled binaries
│   ├── output/                  # Simulation outputs
│   ├── logs/                    # Execution logs
│   ├── prof5_results/           # Profiler results
│   ├── dump/                    # Object code dumps
│   └── executions/              # Per-execution workspaces
│
├── modified_codes/              # Generated variant source files
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

---

## Adding New Applications

To add a new application to PaCA:

### Step 1: Create Application Module

Create a new file in `src/apps/` (e.g., `my_app.py`):

```python
# src/apps/my_app.py

MY_APP_CONFIG = {
    "input_file_for_variants": "data/applications/myapp/src/main.cpp",
    "static_sources": [...],
    "operations_map": {'*': 'FMULX', '+': 'FADDX'},
    # ... other config
}

def prepare_environment(base_config):
    """Prepare the execution environment."""
    # Copy required files, setup directories
    pass

def generate_variants(base_config):
    """Generate all variants for this application."""
    pass

def find_variants_to_simulate(base_config):
    """Return list of variants to simulate."""
    pass

def simulate_variant(variant_file, variant_hash, base_config, status_monitor):
    """Simulate a single variant."""
    pass
```

### Step 2: Register Application

Add to `AVAILABLE_APPS` dictionary in `src/run.py`:

```python
AVAILABLE_APPS = {
    # ... existing apps
    "myapp": "apps.my_app",
}
```

### Step 3: Add Source Code

Place your application source code in `data/applications/myapp/src/`.

Use `//anotacao:` comments to mark lines that can be approximated:

```cpp
//anotacao:
float result = a + b * c;
```

---

## Analyzing Results

### Output Directories

| Directory | Description |
|-----------|-------------|
| `storage/output/` | Simulation output files |
| `storage/prof5_results/` | Profiler energy reports |
| `storage/logs/` | Execution logs |
| `storage/executions/[app]_[mode]_[timestamp]/` | Per-execution workspace |

### Tracking Files

| File | Description |
|------|-------------|
| `executed_variants.json` | Successfully executed variants |
| `failed_variants.json` | Failed variants with error info |
| `checkpoint.json` | Resume state for interrupted runs |
| `execution_info.json` | Execution metadata |

### Error Metrics

The framework calculates:
- **MSE** (Mean Squared Error)
- **MAE** (Mean Absolute Error)
- **MARE** (Mean Absolute Relative Error)
- **Accuracy** (1 - MARE)

---

## Troubleshooting

### Common Issues

#### 1. Missing RISC-V Toolchain

**Error**: `riscv32-unknown-elf-g++: command not found`

**Solution**: Ensure the RISC-V toolchain is in your PATH:
```bash
export PATH=$PATH:/opt/riscv/bin
```

#### 2. Missing Spike Simulator

**Error**: `spike: command not found`

**Solution**: Add Spike to your PATH:
```bash
export PATH=$PATH:/opt/riscv/bin
```

#### 3. No Modifiable Lines Found

**Error**: `[WARNING] No modifiable lines found`

**Solution**: Add `//anotacao:` comments before lines you want to approximate:
```cpp
//anotacao:
float x = a + b;
```

#### 4. Memory Issues with Large Variant Sets

**Solution**: Use tree pruning mode with appropriate threshold:
```bash
python src/run.py --app fft --arvorePoda --threshold 0.03 --alpha 0.8
```

#### 5. Checkpoint Resume

**Prompt**: `Found checkpoint with X/Y variants processed. Continue? (s/n):`

**Solution**: 
- Type `s` or `y` to continue from checkpoint
- Type `n` to start fresh

---

## License

Academic project. All rights reserved.

For questions and support, please contact the development team.

---

## Citation

If you use PaCA in your research, please cite:

```bibtex
@software{paca,
  title = {PaCA: Project for Approximate Computing Analysis},
  author = {Development Team},
  year = {2024},
  url = {https://github.com/your-repo/paca}
}
```
