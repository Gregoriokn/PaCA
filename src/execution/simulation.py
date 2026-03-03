"""
Simulation Module for PaCA

This module handles the execution of compiled variants using the Spike RISC-V
simulator for timing and instruction counting.

Key functionalities:
- Spike simulation execution and timing
- Instruction counting via Spike logs
- Dump file generation for analysis
- Modified line tracking

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

import os
import time
import subprocess
import logging
from typing import Optional
from utils.file_utils import short_hash, TempFiles
from database.variant_tracker import add_executed_variant


def run_spike_simulation(
    exe_file: str, 
    input_file: str, 
    output_file: str, 
    spike_log_file: str, 
    variant_id: str, 
    status_monitor
) -> Optional[float]:
    """
    Executes a variant using the RISC-V Spike simulator.
    
    Runs the compiled RISC-V executable with Spike and captures execution time.
    
    Args:
        exe_file: Path to compiled RISC-V executable
        input_file: Input data file for the application
        output_file: Path to save simulation output
        spike_log_file: Path to save Spike execution log
        variant_id: Unique identifier for logging
        status_monitor: Thread-safe status tracker
        
    Returns:
        float: Execution time in seconds, or None on error
    """
    # Ensure RISC-V toolchain is in PATH
    riscv_path = "/opt/riscv/bin"
    if riscv_path not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{riscv_path}:{os.environ.get('PATH', '')}"
    
    status_monitor.update_status(variant_id, "Simulating with Spike")
    logging.info(f"[Variant {variant_id}] Starting Spike simulation...")
    
    # Create empty output file (required by spike)
    open(output_file, 'w').close()
    os.chmod(output_file, 0o666)
    
    # Spike command execution
    sim_cmd = [
        "spike",
        "--isa=RV32IMAFDC",
        "-c",
        f"--log={spike_log_file}",
        "/opt/riscv/riscv32-unknown-elf/bin/pk",
        exe_file,
        input_file,
        output_file
    ]
    
    # Execute and measure time
    start = time.perf_counter()
    try:
        result = subprocess.run(
            sim_cmd,
            capture_output=True,
            text=True,
            timeout=600  # Adjust if needed
        )
        if result.returncode != 0:
            logging.error(f"[Variant {variant_id}] Simulation error (Spike):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
            print(f"[Variant {variant_id}] Simulation error (Spike):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
            return None
        if result.stderr:
            logging.info(f"[Variant {variant_id}] Spike stderr output: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variant {variant_id}] Simulation error: {e.stderr}")
        status_monitor.update_status(variant_id, "Simulation error")
        return None
    end = time.perf_counter()
    
    runtime = end - start
    logging.info(f"[Variant {variant_id}] Simulation completed in {runtime:.6f} seconds.")
    
    return runtime


def save_modified_lines(variant_file: str, original_file: str, variant_hash: str, config, code_parser) -> None:
    """
    Saves the list of modified lines to a text file for analysis.
    
    Identifies which lines were changed by comparing the variant with original.
    
    Args:
        variant_file: Path to variant source
        original_file: Path to original source
        variant_hash: Unique variant identifier
        config: Configuration dictionary
        code_parser: Code parser module
    """
    lines_output_file = os.path.join(config["outputs_dir"], f"linhas_hash_{variant_hash}.txt")
    
    # Read original and variant code
    with open(original_file, "r") as f:
        original_lines = f.readlines()
    with open(variant_file, "r") as f:
        modified_lines = f.readlines()
    
    # Get physical-to-logical mapping
    _, __, physical_to_logical = code_parser(original_file)
    
    # Get modified logical lines
    modified_logical_lines = get_modified_logical_lines(original_lines, modified_lines, physical_to_logical)
    
    # Save to file
    with open(lines_output_file, "w") as f:
        for line in modified_logical_lines:
            f.write(str(line) + "\n")
    
    logging.info(f"Modified lines saved for variant {short_hash(variant_hash)}")


def get_modified_logical_lines(original_lines: list, modified_lines: list, physical_to_logical: dict) -> list:
    """
    Identifies logical line numbers that were modified between files.
    
    First finds lines marked with //anotacao:, then checks which of those
    were actually changed in the variant.
    
    Args:
        original_lines: Original source lines
        modified_lines: Variant source lines
        physical_to_logical: Mapping from physical to logical line numbers
        
    Returns:
        List of modified logical line numbers (sorted)
    """
    import re
    
    modifiable_lines = []
    for i, line in enumerate(original_lines):
        if re.match(r'^\s*//anotacao:\s*$', line):
            if i + 1 < len(original_lines):
                modifiable_lines.append(i + 1)
    
    # Check which of these lines were actually modified
    modified_logical_lines = []
    for physical_line in modifiable_lines:
        if physical_line < len(original_lines) and physical_line < len(modified_lines):
            orig = re.sub(r'\s+', ' ', original_lines[physical_line].strip())
            mod = re.sub(r'\s+', ' ', modified_lines[physical_line].strip())
            
            if orig != mod and physical_line in physical_to_logical:
                modified_logical_lines.append(physical_to_logical[physical_line])
    
    return sorted(modified_logical_lines)
