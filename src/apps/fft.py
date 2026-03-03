"""
FFT (Fast Fourier Transform) Application Module for PaCA

This module provides complete support for generating, compiling, simulating,
and analyzing approximate FFT variants on RISC-V architecture.

The FFT implementation uses approximate floating-point operators (FADDX, FMULX, FSUBX)
to reduce energy consumption at the cost of computational accuracy.

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

import os
import glob
import subprocess
import sys
import shutil
import logging
import json

from code_parser import parse_code
from hash_utils import gerar_hash_codigo_logico
from database.variant_tracker import load_executed_variants
from utils.file_utils import short_hash, copy_file, TempFiles
from transformations import detect_operations_per_line, save_operations_json
from execution.compilation import generate_dump
from execution.simulation import run_spike_simulation
from transformations import apply_transformation
from utils.prof5fake import contar_instrucoes_log, avaliar_modelo_energia

FFT_CONFIG = {
    "app_name": "fft",
    "input_file_for_variants": "data/applications/fft/src/fourier.cpp",
    "fourier_source_file": "data/applications/fft/src/fourier.cpp", 
    
    # Source files that are compiled together but do NOT undergo mutation
    "static_sources": [
        "data/applications/fft/src/fft.cpp",      # Contains the main function
        "data/applications/fft/src/complex.cpp"   # Dependency for complex.hpp
    ],
    
    # Input argument for simulation (vector size)
    "train_data_input": "512", 
    
    # File patterns and suffixes
    "source_pattern": "fourier_*.cpp", 
    "exe_prefix": "fourier_",
    "output_suffix": ".data",
    "time_suffix": ".time",
    "prof5_suffix": ".prof5",
    
    # Energy model required for profiling
    "prof5_model": "data/models/APPROX_1.json", 
    
    # Operation mapping for approximation
    "operations_map": {'*': 'FMULX', '+': 'FADDX', '-': 'FSUBX'},
    
    # Include directories
    "include_dir": "data/applications/fft/src",
    "optimization_level": "-O"
}


def cleanup_variant_files(variant_hash, config, preserve_logs=True):
    """
    Removes temporary files (logs, dumps) while preserving results (.prof5, .time).
    
    Args:
        variant_hash: Unique identifier for the variant
        config: Configuration dictionary
        preserve_logs: If True, keeps the Spike log files for debugging
    """
    exe_prefix = config["exe_prefix"]
    logs_dir = config["logs_dir"]
    dump_dir = config["dump_dir"]
    app_name = config.get("app_name", "fft")
    spike_log_file = os.path.join(logs_dir, f"{app_name}_{variant_hash}.json")
    dump_file = os.path.join(dump_dir, f"dump_{variant_hash}.txt")
    
    # Always remove spike log (unless preserve_logs=True for debugging)
    if not preserve_logs and os.path.exists(spike_log_file):
        try:
            os.remove(spike_log_file)
        except OSError:
            logging.debug(f"Could not remove {spike_log_file}")
    
    # Always remove dump files (they're large)
    if os.path.exists(dump_file):
        try:
            os.remove(dump_file)
        except OSError:
            logging.debug(f"Could not remove {dump_file}")


def run_prof5_fake(spike_log_file, prof5_model, prof5_time_file, prof5_report_path, variant_id, status_monitor):
    """
    Executes Prof5Fake to estimate energy and performance from Spike simulation logs.
    
    This function:
    1. Parses the Spike execution log to count instructions
    2. Applies the energy model to estimate consumption
    3. Saves latency and detailed energy reports
    
    Args:
        spike_log_file: Path to Spike simulation log
        prof5_model: Path to energy model JSON file
        prof5_time_file: Output file for latency (ms)
        prof5_report_path: Output file for detailed energy report
        variant_id: Unique identifier for logging
        status_monitor: Thread-safe status tracker
        
    Returns:
        float: Latency in milliseconds, or None on error
    """
    try:
        status_monitor.update_status(variant_id, "Running Prof5Fake")
        
        if not os.path.exists(spike_log_file):
            logging.error(f"[Variant {variant_id}] Spike log not found: {spike_log_file}")
            return None
            
        instrucoes_dict = contar_instrucoes_log(spike_log_file)
        if not instrucoes_dict:
            logging.error(f"[Variant {variant_id}] Failed to count instructions.")
            return None
            
        # Fallback for energy model
        if not prof5_model or not os.path.exists(prof5_model):
            default_model = "data/profiles/riscv_energy_model.json"
            if os.path.exists(default_model):
                prof5_model = default_model
            else:
                logging.error(f"[Variant {variant_id}] Energy model not found: {prof5_model}")
                return None

        resultados_energia = avaliar_modelo_energia(instrucoes_dict, prof5_model)
        if not resultados_energia:
            return None
            
        # Save detailed JSON report
        os.makedirs(os.path.dirname(prof5_report_path), exist_ok=True)
        with open(prof5_report_path, 'w') as f:
            json.dump(resultados_energia, f, indent=2, sort_keys=True)
        
        # Save latency for run.py to read
        latency_ms = resultados_energia["summary"]["latency_ms"]
        with open(prof5_time_file, 'w') as f:
            f.write(f"{latency_ms}\n")
        
        status_monitor.update_status(variant_id, "Prof5Fake Completed")
        return latency_ms
        
    except Exception as e:
        logging.error(f"[Variant {variant_id}] Error in Prof5Fake: {e}", exc_info=True)
        return None


def get_pruning_config(base_config):
    """
    Returns the configuration required for tree pruning mode.
    
    Parses the source file to identify modifiable lines and builds the
    necessary data structures for the pruning algorithm.
    
    Args:
        base_config: Base configuration dictionary
        
    Returns:
        dict: Configuration for tree pruning including parsed source info
    """
    config = {**base_config, **FFT_CONFIG}
    source_file = config["input_file_for_variants"]
    original_lines, modifiable_lines, physical_to_logical = parse_code(source_file)
    return {
        "source_file": source_file,
        "original_lines": original_lines,
        "modifiable_lines": modifiable_lines,
        "physical_to_logical": physical_to_logical,
        "app_specific_config": config
    }


def generate_specific_variant(original_lines, physical_to_logical, modified_line_indices, config):
    """
    Generates a C++ source file for a specific variant with modifications applied.
    
    This function is used by tree pruning mode to create individual variants
    on-demand rather than pre-generating all combinations.
    
    Args:
        original_lines: List of original source lines
        physical_to_logical: Mapping from physical to logical line numbers
        modified_line_indices: Indices of lines to modify
        config: Application configuration
        
    Returns:
        tuple: (path to generated variant file, variant hash)
    """
    modified_lines_content = list(original_lines)
    for idx in modified_line_indices:
        orig = modified_lines_content[idx]
        transformed = apply_transformation(orig, config["operations_map"])
        # Preserve original line ending
        if not transformed.endswith("\n") and orig.endswith("\n"):
            transformed = transformed + "\n"
        modified_lines_content[idx] = transformed

    variant_hash = gerar_hash_codigo_logico(modified_lines_content, physical_to_logical)
    
    variant_dir = config.get("input_dir", "storage/variantes")
    base_name, ext = os.path.splitext(os.path.basename(config["input_file_for_variants"]))
    variant_filepath = os.path.join(variant_dir, f"{base_name}_{variant_hash}{ext}")

    os.makedirs(variant_dir, exist_ok=True)
    with open(variant_filepath, 'w', encoding='utf-8') as f:
        f.writelines(modified_lines_content)
        
    return variant_filepath, variant_hash


def prepare_environment(base_config):
    """
    Prepares the execution environment for FFT.
    
    Copies required header files (approx.h) to the variant directory.
    
    Args:
        base_config: Base configuration dictionary
        
    Returns:
        bool: True if successful, False otherwise
    """
    config = {**base_config, **FFT_CONFIG}
    approx_source = config.get("approx_file", "data/reference/approx.h")
    return copy_file(approx_source, config["input_dir"])


def generate_variants(base_config):
    """
    Generates all FFT variants by calling the variant generator script.
    
    This function invokes src/gera_variantes.py to perform combinatorial
    generation of all possible approximate variants.
    
    Args:
        base_config: Base configuration dictionary
        
    Returns:
        bool: True if variants were generated successfully
    """
    config = {**base_config, **FFT_CONFIG}
    output_dir = os.path.abspath(config.get("input_dir"))
    input_path = os.path.abspath(config["input_file_for_variants"])
    executados = os.path.abspath(config.get("executed_variants_file", ""))
    
    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        sys.executable, "src/gera_variantes.py",
        "--input", input_path,
        "--output", output_dir,
        "--strategy", "all"
    ]
    
    if executados and os.path.exists(executados):
        cmd += ["--executados", executados]

    logging.info(f"Generating FFT variants: {' '.join(cmd)}")
    
    try:
        env = os.environ.copy()
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        env["PYTHONPATH"] = project_root + os.pathsep + env.get("PYTHONPATH", "")

        result = subprocess.run(
            cmd, 
            cwd=project_root, 
            capture_output=True, 
            text=True, 
            timeout=1800,  # 30 minute timeout
            env=env
        )
        
        if result.returncode != 0:
            logging.error(f"Error in variant generation subprocess:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
            # Fallback attempt
            try:
                logging.info("Attempting fallback via direct import...")
                sys.path.append(project_root)
                from gera_variantes import main as gera_main
                from config import update_config
                opts = {
                    "input_file": input_path, 
                    "output_folder": output_dir, 
                    "executed_variants_file": executados,
                    "strategy": "all"
                }
                update_config(opts)
                return gera_main()
            except Exception as e:
                logging.error(f"Fallback failed: {e}")
                return False
        
        # Check if files were generated
        pattern = os.path.join(output_dir, config["source_pattern"])
        if not glob.glob(pattern):
            logging.warning("Process ran but no files found in destination.")
            return False

        return True
            
    except Exception as e:
        logging.error(f"Fatal exception in variant generation: {e}")
        return False


def find_variants_to_simulate(base_config):
    """
    Lists all available variants ready for simulation.
    
    Scans the input directory for generated variant files and filters out
    already-executed variants based on the tracking database.
    
    Args:
        base_config: Base configuration dictionary
        
    Returns:
        tuple: (list of (filepath, hash) pairs, physical_to_logical mapping)
    """
    config = {**base_config, **FFT_CONFIG}
    input_dir = config.get("input_dir")
    pattern = os.path.join(input_dir, config["source_pattern"])
    
    # Try to generate if none exist
    if not glob.glob(pattern):
        generate_variants(base_config)
        
    files = sorted(glob.glob(pattern))
    executed = set()
    try:
        executed = set(load_executed_variants(config.get("executed_variants_file", "")))
    except: pass

    source_file = config["input_file_for_variants"]
    try:
        _, _, physical_to_logical = parse_code(source_file)
    except: physical_to_logical = None

    to_run = []
    # Add original version
    try:
        with open(source_file, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines(keepends=True)
        h = gerar_hash_codigo_logico(lines, physical_to_logical)
        if h not in executed: 
            to_run.append((source_file, h))
    except: pass

    for f in files:
        if os.path.abspath(f) == os.path.abspath(source_file): continue
        try:
            with open(f, 'r', encoding='utf-8') as fh: 
                lines = fh.readlines()
            h = gerar_hash_codigo_logico(lines, physical_to_logical)
            if h not in executed: 
                to_run.append((f, h))
        except: pass
        
    return to_run, physical_to_logical


def compile_fft_variant(fourier_cpp_to_compile, output_naming_hash, config, status_monitor):
    """
    Compiles the FFT application linking the variant fourier.cpp with static sources.
    
    The compilation process:
    1. Compile static sources (fft.cpp, complex.cpp) to object files
    2. Compile the variant (fourier.cpp) to object file
    3. Link all objects into final executable
    
    Args:
        fourier_cpp_to_compile: Path to fourier.cpp variant
        output_naming_hash: Hash for naming output files
        config: Configuration dictionary
        status_monitor: Status tracker
        
    Returns:
        tuple: (success boolean, path to executable)
    """
    is_original = (os.path.abspath(fourier_cpp_to_compile) == os.path.abspath(config["fourier_source_file"]))
    variant_id = "original" if is_original else short_hash(output_naming_hash)
    status_monitor.update_status(variant_id, "Compiling FFT")

    exe_prefix = config.get("exe_prefix", "fourier_")
    executables_dir = config["executables_dir"]
    optimization = config.get("optimization_level", "-O")
    
    objects_to_link = []
    include_flags = ["-I", config["include_dir"], "-I", config["input_dir"]]

    # 1. Compile Static files (fft.cpp, complex.cpp)
    for static_src in config["static_sources"]:
        base_name = os.path.basename(static_src).replace('.cpp', '')
        obj_name = f"{exe_prefix}{output_naming_hash}_{base_name}.o"
        obj_path = os.path.join(executables_dir, obj_name)
        
        cmd = ["riscv32-unknown-elf-g++", "-march=rv32imafdc", optimization, *include_flags, "-c", static_src, "-o", obj_path, "-lm"]
        if subprocess.run(cmd, capture_output=True).returncode != 0:
            status_monitor.update_status(variant_id, f"Compilation Error {base_name}")
            return False, None
        objects_to_link.append(obj_path)

    # 2. Compile Variant (fourier.cpp)
    variant_obj = os.path.join(executables_dir, f"{exe_prefix}{output_naming_hash}_fourier.o")
    cmd_var = ["riscv32-unknown-elf-g++", "-march=rv32imafdc", optimization, *include_flags, "-c", fourier_cpp_to_compile, "-o", variant_obj, "-lm"]
    if subprocess.run(cmd_var, capture_output=True).returncode != 0:
        status_monitor.update_status(variant_id, "Compilation Error fourier")
        return False, None
    objects_to_link.append(variant_obj)

    # 3. Final Linking
    exe_file = os.path.join(executables_dir, f"{exe_prefix}{output_naming_hash}")
    cmd_link = ["riscv32-unknown-elf-g++", "-march=rv32imafdc", *objects_to_link, "-o", exe_file, "-lm"]
    if subprocess.run(cmd_link, capture_output=True).returncode != 0:
        status_monitor.update_status(variant_id, "Linking Error")
        return False, None

    os.chmod(exe_file, 0o755)
    return True, exe_file


def run_profiling_stage(resume_context, base_config, status_monitor):
    """
    Executes the profiling stage (called separately or from unified flow).
    
    Runs Prof5Fake on the Spike log to estimate energy consumption.
    
    Args:
        resume_context: Dictionary with simulation context (log paths, hashes, etc.)
        base_config: Base configuration
        status_monitor: Status tracker
        
    Returns:
        bool: True if profiling succeeded
    """
    config = {**base_config, **FFT_CONFIG}
    spike_log_file = resume_context["spike_log_file"]
    variant_id = resume_context["variant_id"]
    prof5_time_file = resume_context["prof5_time_file"]
    prof5_report_path = resume_context["prof5_report_path"]
    variant_hash = resume_context["variant_hash"]
    
    try:
        status_monitor.update_status(variant_id, "Starting Profiling")
        prof5_time = run_prof5_fake(
            spike_log_file, config.get("prof5_model"), prof5_time_file, prof5_report_path,
            variant_id, status_monitor
        )
        if prof5_time is None:
            return False
            
        try:
            # Try to save modified lines using LOGICAL lines (for consistent dataset)
            variant_filepath = resume_context["variant_filepath"]
            original_filepath = config["fourier_source_file"]
            if os.path.exists(variant_filepath) and os.path.exists(original_filepath):
                # Get physical_to_logical mapping
                _, _, physical_to_logical = parse_code(original_filepath)
                
                with open(variant_filepath, 'r') as f_v, open(original_filepath, 'r') as f_o:
                    v_lines = f_v.readlines()
                    o_lines = f_o.readlines()
                
                # Find physical lines that changed
                physical_modified = [i+1 for i, (l1, l2) in enumerate(zip(o_lines, v_lines)) if l1 != l2]
                
                # Convert to logical lines (use physical-1 as fallback for lines after annotations)
                mod_indices = []
                for p in physical_modified:
                    if p in physical_to_logical:
                        mod_indices.append(physical_to_logical[p])
                    elif (p - 1) in physical_to_logical:
                        # Line after annotation - try the annotation line itself
                        mod_indices.append(physical_to_logical[p - 1])
                    else:
                        # Use physical line as last resort
                        mod_indices.append(p)
                mod_indices = sorted(set(mod_indices))
                
                if mod_indices:
                    save_modified_lines_txt(mod_indices, variant_hash, config)
                
                # Detect and save operations per line (use logical key with physical fallback)
                operations_per_line = detect_operations_per_line(
                    o_lines, v_lines, physical_to_logical, config.get("operations_map", {})
                )
                if operations_per_line:
                    operacoes_dir = config.get("operacoes_dir", "storage/operacoes")
                    os.makedirs(operacoes_dir, exist_ok=True)
                    operacoes_path = os.path.join(operacoes_dir, f"operacoes_{variant_hash}.json")
                    save_operations_json(operations_per_line, operacoes_path)
        except Exception as e:
            import traceback
            logging.error(f"Failed to save modified lines: {e}")
            traceback.print_exc()

        status_monitor.update_status(variant_id, "FFT Completed")
        return True
    finally:
        cleanup_variant_files(variant_hash, config)


def simulate_variant(current_variant_filepath, current_variant_hash, base_config, status_monitor, only_spike=False):
    """
    Executes the complete flow: Compilation -> Simulation (Spike) -> Profiling.
    
    This is the main entry point for simulating a single FFT variant.
    
    Args:
        current_variant_filepath: Path to variant source file
        current_variant_hash: Unique hash for this variant
        base_config: Base configuration
        status_monitor: Status tracker
        only_spike: If True, only run Spike simulation (skip Prof5)
        
    Returns:
        tuple: (output_file_path, resume_context or None)
    """
    config = {**base_config, **FFT_CONFIG}
    is_original = (os.path.abspath(current_variant_filepath) == os.path.abspath(config["fourier_source_file"]))
    variant_id = "original" if is_original else short_hash(current_variant_hash)

    exe_prefix = config["exe_prefix"]
    outputs_dir = config["outputs_dir"]
    logs_dir = config["logs_dir"]
    dump_dir = config["dump_dir"]
    prof5_results_dir = config["prof5_results_dir"]
    app_name = config.get("app_name", "fft")

    spike_output_file = os.path.join(outputs_dir, f"{exe_prefix}{current_variant_hash}{config['output_suffix']}")
    time_file = os.path.join(outputs_dir, f"{exe_prefix}{current_variant_hash}{config['time_suffix']}")
    prof5_time_file = os.path.join(outputs_dir, f"{exe_prefix}{current_variant_hash}{config['prof5_suffix']}")
    spike_log_file = os.path.join(logs_dir, f"{app_name}_{current_variant_hash}.json")
    dump_file = os.path.join(dump_dir, f"dump_{current_variant_hash}.txt")
    prof5_report_path = os.path.join(prof5_results_dir, f"prof5_results_{current_variant_hash}.json")

    # 1. Compilation
    compiled_ok, exe_file = compile_fft_variant(current_variant_filepath, current_variant_hash, config, status_monitor)
    if not compiled_ok: return (None, None) if only_spike else False

    # 2. Dump Generation
    if not generate_dump(exe_file, dump_file, variant_id, status_monitor): 
        return (None, None) if only_spike else False

    # 3. Spike Simulation
    sim_time = run_spike_simulation(exe_file, config["train_data_input"], spike_output_file, spike_log_file, variant_id, status_monitor)
    if sim_time is None: return (None, None) if only_spike else False
    
    with open(time_file, 'w') as tf: tf.write(f"{sim_time}\n")
    try: os.chmod(time_file, 0o666)
    except: pass

    resume_context = {
        "exe_file": exe_file, "spike_log_file": spike_log_file, "dump_file": dump_file,
        "variant_id": variant_id, "variant_filepath": current_variant_filepath,
        "variant_hash": current_variant_hash, "prof5_time_file": prof5_time_file,
        "prof5_report_path": prof5_report_path,
    }

    if only_spike: return spike_output_file, resume_context
    
    # 4. Profiling (if only_spike=False, run immediately)
    success = run_profiling_stage(resume_context, base_config, status_monitor)
    return spike_output_file, None if success else None


def save_modified_lines_txt(node_modified_lines, variant_hash, config):
    """
    Saves the list of modified line indices to a text file.
    
    This is used for analysis and debugging to understand which
    operations were approximated in each variant.
    
    Args:
        node_modified_lines: List of line indices that were modified
        variant_hash: Unique variant identifier
        config: Configuration dictionary
        
    Returns:
        str: Path to saved file, or None on error
    """
    try:
        linhas_dir = config.get("linhas_modificadas_dir", "storage/linhas_modificadas")
        os.makedirs(linhas_dir, exist_ok=True)
        txt_filepath = os.path.join(linhas_dir, f"linhas_{variant_hash}.txt")
        with open(txt_filepath, 'w', encoding='utf-8') as f:
            for li in node_modified_lines: f.write(f"{li}\n")
        try: os.chmod(txt_filepath, 0o666)
        except: pass
        return txt_filepath
    except Exception: return None


def calculate_custom_error(reference_file, variant_file):
    """
    Calculates Mean Relative Error (MRE) comparing complex FFT output.
    
    The FFT outputs complex numbers in format: Real Imaginary Real Imaginary...
    This function computes the relative error for each component.
    
    Args:
        reference_file: Path to reference (exact) output
        variant_file: Path to variant output
        
    Returns:
        float: Mean Relative Error, or None on calculation failure
    """
    try:
        with open(reference_file, 'r') as f_ref:
            ref_data = [float(x) for x in f_ref.read().split()]
        with open(variant_file, 'r') as f_var:
            var_data = [float(x) for x in f_var.read().split()]

        total_points = len(ref_data)
        if total_points == 0: return 1.0 

        if len(ref_data) != len(var_data):
            min_len = min(len(ref_data), len(var_data))
            ref_data = ref_data[:min_len]
            var_data = var_data[:min_len]
            total_points = min_len

        sum_relative_error = 0.0
        epsilon = 1e-10 
        for r, v in zip(ref_data, var_data):
            val_ref = abs(r)
            diff = abs(r - v)
            if val_ref < epsilon:
                relative_error = diff / (val_ref + epsilon)
            else:
                relative_error = diff / val_ref
            sum_relative_error += relative_error
        
        return sum_relative_error / total_points
    except Exception as e:
        logging.error(f"[FFT Error] Failed to calculate MRE: {e}")
        return None
