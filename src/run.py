#!/usr/bin/env python3
"""
PaCA (Project for Approximate Computing Analysis) - Main Execution Script

This module orchestrates the complete workflow for approximate computing variant
analysis, including:
- Variant generation and compilation
- RISC-V simulation via Spike
- Energy profiling via Prof5
- Error analysis against reference
- Tree-based pruning optimization
- Parallel execution support

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

import os
import sys
import argparse
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import deque
import logging
import threading
import json

from config_base import BASE_CONFIG
from database.variant_tracker import add_executed_variant, add_failed_variant
from code_parser import parse_code
from utils.logger import setup_logging, VariantStatusMonitor
from utils.file_utils import ensure_dirs, short_hash, generate_report, save_checkpoint, load_checkpoint
from hash_utils import gerar_hash_codigo_logico

from utils.pruning_tree import build_variant_tree, prune_branch, save_tree_to_file, save_tree_to_dot
from utils.error_analyzer import calculate_error

AVAILABLE_APPS = {
    "blackscholes": "apps.blackscholes",
    "inversek2j": "apps.inversek2j",
    "fft": "apps.fft",
    "jmeint": "apps.jmeint",
    "kmeans": "apps.kmeans",
    "sobel": "apps.sobel"
}


def get_cleanup_config(config):
    """
    Returns the correct cleanup configuration, regardless of execution mode.
    Resolves KeyError issue in Brute Force mode.
    
    Args:
        config: Execution configuration dictionary
        
    Returns:
        dict: Cleaned configuration for variant cleanup
    """
    if 'pruning_config' in config and 'app_specific_config' in config['pruning_config']:
        return {**config['base_config'], **config['pruning_config']['app_specific_config']}
    return config


def save_modified_lines_for_bruteforce(variant_file, original_file, variant_hash, app_module, config):
    """
    Compares a variant with the original source and saves indices of modified lines.
    This is used for tracking which lines were changed to generate each variant.
    
    Args:
        variant_file: Path to the generated variant source file
        original_file: Path to the original source file
        variant_hash: Unique hash identifier for the variant
        app_module: Application-specific module with configuration
        config: Execution configuration dictionary
    """
    if not hasattr(app_module, 'save_modified_lines_txt'):
        return

    try:
        import inspect
        sig = inspect.signature(app_module.save_modified_lines_txt)
        params = list(sig.parameters)
        if len(params) == 4:
            app_module.save_modified_lines_txt(variant_file, original_file, variant_hash, config)
        else:
            # Get physical_to_logical mapping for logical line conversion
            _, _, physical_to_logical = parse_code(original_file)
            
            with open(variant_file, 'r') as f_variant, open(original_file, 'r') as f_original:
                variant_lines = f_variant.readlines()
                original_lines = f_original.readlines()
            
            max_len = max(len(variant_lines), len(original_lines))
            variant_lines.extend([''] * (max_len - len(variant_lines)))
            original_lines.extend([''] * (max_len - len(original_lines)))
            
            physical_modified = [i+1 for i, (line1, line2) in enumerate(zip(original_lines, variant_lines)) if line1 != line2]
            
            # Convert to logical lines (use physical-1 as fallback for lines after annotations)
            modified_indices = []
            for p in physical_modified:
                if p in physical_to_logical:
                    modified_indices.append(physical_to_logical[p])
                elif (p - 1) in physical_to_logical:
                    modified_indices.append(physical_to_logical[p - 1])
                else:
                    modified_indices.append(p)
            modified_indices = sorted(set(modified_indices))
            
            if modified_indices:
                app_module.save_modified_lines_txt(modified_indices, variant_hash, config)
            else:
                logging.warning(f"No difference found between variant {short_hash(variant_hash)} and original.")

    except FileNotFoundError:
        logging.warning(f"Original file '{original_file}' or variant file '{variant_file}' not found for saving modified lines.")
    except Exception as e:
        logging.error(f"Failed to save modified line indices for hash {variant_hash}: {e}")


def create_execution_workspace(app_name, execution_mode, base_config):
    """
    Creates a dedicated workspace for a specific execution run.
    All outputs (executables, logs, results) are organized in timestamped directories.
    
    Args:
        app_name: Name of the application being executed
        execution_mode: 'forcabruta' (brute force) or 'arvorepoda' (tree pruning)
        base_config: Base configuration dictionary
        
    Returns:
        dict: Extended configuration with workspace paths
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    workspace_name = f"{app_name}_{execution_mode}_{timestamp}"
    workspace_path = os.path.join("storage", "executions", workspace_name)
    
    execution_config = base_config.copy()
    execution_config.update({
        "workspace_path": workspace_path,
        "executables_dir": os.path.join(workspace_path, "executables"),
        "outputs_dir": os.path.join(workspace_path, "outputs"),
        "input_dir": os.path.join(workspace_path, "variants"),
        "logs_dir": os.path.join(workspace_path, "logs"),
        "prof5_results_dir": os.path.join(workspace_path, "prof5_results"),
        "dump_dir": os.path.join(workspace_path, "dumps"),
        "linhas_modificadas_dir": os.path.join(workspace_path, "linhas_modificadas"),
        "operacoes_dir": os.path.join(workspace_path, "operacoes"),
        "executed_variants_file": os.path.join(workspace_path, "executed_variants.json"),
        "failed_variants_file": os.path.join(workspace_path, "failed_variants.json"),
        "checkpoint_file": os.path.join(workspace_path, "checkpoint.json")
    })
    
    ensure_dirs(
        execution_config["executables_dir"],
        execution_config["outputs_dir"], 
        execution_config["input_dir"],
        execution_config["logs_dir"],
        execution_config["prof5_results_dir"],
        execution_config["dump_dir"],
        execution_config["linhas_modificadas_dir"],
        execution_config["operacoes_dir"]
    )
    
    execution_info = {
        "app_name": app_name,
        "execution_mode": execution_mode,
        "timestamp": timestamp,
        "start_time": datetime.now().isoformat(),
        "workspace_path": workspace_path,
        "base_storage": base_config.get("storage_root", "storage")
    }
    
    info_file = os.path.join(workspace_path, "execution_info.json")
    with open(info_file, 'w') as f:
        json.dump(execution_info, f, indent=2)
    
    logging.info(f"Workspace created: {workspace_path}")
    return execution_config


def check_dependencies():
    """
    Verifies that all required external tools are available in the system.
    Checks for RISC-V compiler, objdump, and Spike simulator.
    
    Returns:
        bool: True if all dependencies are found, False otherwise
    """
    import shutil
    tools = ["riscv32-unknown-elf-g++", "riscv32-unknown-elf-objdump", "spike"]
    missing = [tool for tool in tools if not shutil.which(tool)]
    if missing:
        logging.error(f"Required tools not found: {', '.join(missing)}")
        return False
    return True


def setup_environment(app_name, execution_config):
    """
    Sets up the execution environment for a specific application.
    Generates variants and prepares the application-specific environment.
    
    Args:
        app_name: Name of the application to set up
        execution_config: Extended configuration with workspace paths
        
    Returns:
        module: Imported application module, or False on failure
    """
    os.environ["PATH"] += ":/opt/riscv/bin"
    
    if app_name not in AVAILABLE_APPS:
        logging.error(f"Error: Application '{app_name}' not found.")
        return False
    
    try:
        app_module = __import__(AVAILABLE_APPS[app_name], fromlist=[''])
    except ImportError as e:
        logging.error(f"Error: Could not import module '{AVAILABLE_APPS[app_name]}': {e}")
        return False
    
    logging.info("Generating all variants for this execution...")
    app_module.generate_variants(execution_config)
    
    if not app_module.prepare_environment(execution_config):
        logging.error(f"Error: Failed to prepare environment for '{app_name}'")
        return False
    
    return app_module


def process_node(node, app_module, config, threshold, reference_output_path, status_monitor, db_lock, original_energy, alpha):
    """
    Processes a single node in the variant tree:
    1. Generates the specific variant for this node
    2. Runs complete simulation (Spike + Prof5)
    3. Calculates error against reference
    4. Calculates energy savings
    5. Applies pruning heuristic
    
    Args:
        node: VariantNode representing this variant combination
        app_module: Application-specific module
        config: Full configuration dictionary
        threshold: Maximum allowed cost for acceptance
        reference_output_path: Path to reference output for error calculation
        status_monitor: Thread-safe status tracker
        db_lock: Lock for database operations
        original_energy: Energy consumption of original (non-approximated) version
        alpha: Weight for error in cost function (energy weight = 1 - alpha)
        
    Returns:
        VariantNode: Updated node with status, error, energy, and cost
    """
    if node.status != 'PENDING':
        return node

    node.status = 'SIMULATING'
    cleanup_conf = get_cleanup_config(config)

    try:
        variant_filepath, variant_hash = app_module.generate_specific_variant(
            config['pruning_config']['original_lines'],
            config['pruning_config']['physical_to_logical'],
            node.modified_lines,
            config['pruning_config']['app_specific_config']
        )
        node.variant_hash = variant_hash
    except Exception as e:
        logging.error(f"Error generating specific variant for node {node.name}: {e}")
        node.status = 'FAILED'
        return node

    try:
        variant_output_path, _ = app_module.simulate_variant(
            variant_filepath, variant_hash, config['base_config'], status_monitor, only_spike=False
        )
    except Exception as e:
        logging.error(f"Exception during unified simulation of node {node.name}: {e}")
        variant_output_path = None

    if variant_output_path is None:
        node.status = 'FAILED'
        add_failed_variant(variant_hash, "simulation_failure", config['base_config']["failed_variants_file"], lock=db_lock)
        if hasattr(app_module, 'cleanup_variant_files'):
            app_module.cleanup_variant_files(variant_hash, cleanup_conf)
        prune_branch(node)
        return node

    error = None
    if hasattr(app_module, 'calculate_custom_error'):
        error = app_module.calculate_custom_error(reference_output_path, variant_output_path)
    else:
        accuracy_data = calculate_error(reference_output_path, variant_output_path)
        if accuracy_data is not None:
            try:
                if isinstance(accuracy_data, dict):
                    accuracy_val = float(accuracy_data.get('accuracy', list(accuracy_data.values())[0]))
                else:
                    accuracy_val = float(accuracy_data)
                error = 1.0 - accuracy_val
            except Exception as e:
                logging.error(f"Error converting accuracy to error: {e}")
                error = None

    if error is None:
        node.status = 'FAILED'
        add_failed_variant(variant_hash, "error_calculation_failure", config['base_config']["failed_variants_file"], lock=db_lock)
        if hasattr(app_module, 'cleanup_variant_files'):
            app_module.cleanup_variant_files(variant_hash, cleanup_conf)
        prune_branch(node)
        return node

    node.error = error

    prof5_file_pattern = os.path.join(config['base_config']["outputs_dir"], f"*{variant_hash}*.prof5")
    possible_files = glob.glob(prof5_file_pattern)
    
    current_energy = float('inf')
    if possible_files:
        prof5_file = possible_files[0]
        try:
            with open(prof5_file, 'r') as f:
                current_energy = float(f.read().strip())
        except Exception as e:
            logging.error(f"Failed to read energy for {node.name} in file {prof5_file}: {e}")

    node.energy = current_energy

    # Cost Function: Weighted combination of Error and Energy Reduction
    energy_ratio = current_energy / original_energy if original_energy > 0 else 1.0
    heuristic_cost = (alpha * error) + ((1 - alpha) * energy_ratio)
    node.cost = heuristic_cost

    if hasattr(app_module, 'save_modified_lines_txt'):
        app_module.save_modified_lines_txt(node.modified_lines, variant_hash, config['base_config'])

    if heuristic_cost > threshold:
        node.status = 'PRUNED'
        prune_branch(node)
        logging.info(f"Node {node.name} pruned. Cost: {heuristic_cost:.4f} (Err: {error:.4f}, E_Ratio: {energy_ratio:.4f}) > Thr: {threshold}")
        if hasattr(app_module, 'cleanup_variant_files'):
            app_module.cleanup_variant_files(variant_hash, cleanup_conf)
    else:
        node.status = 'COMPLETED'
        logging.info(f"Node {node.name} accepted. Cost: {heuristic_cost:.4f} <= Thr: {threshold}")
        add_executed_variant(variant_hash, config['base_config']["executed_variants_file"], lock=db_lock)

    return node


def run_tree_pruning_mode(app_module, execution_config, status_monitor, args, db_lock):
    """
    Executes the Tree Pruning mode for intelligent variant space exploration.
    
    This mode builds a variant tree where:
    - Root represents the original (non-approximated) code
    - Each level adds one more approximated operation
    - Branches are pruned based on heuristic cost (error + energy)
    
    The algorithm processes level-by-level, pruning unpromising branches early.
    
    Args:
        app_module: Application-specific module
        execution_config: Extended configuration with workspace paths
        status_monitor: Thread-safe status tracker
        args: Command-line arguments (threshold, alpha, workers)
        db_lock: Lock for database operations
    """
    logging.info("Initializing Tree Pruning mode...")
    
    pruning_config = app_module.get_pruning_config(execution_config)
    if not pruning_config["modifiable_lines"]:
        logging.warning("No modifiable lines found. Aborting.")
        return

    root = build_variant_tree(pruning_config["modifiable_lines"])
    
    logging.info("Running complete simulation of original version (reference and profiling)...")
    original_hash = gerar_hash_codigo_logico(pruning_config['original_lines'], pruning_config['physical_to_logical'])
    reference_output_path, _ = app_module.simulate_variant(pruning_config['source_file'], original_hash, execution_config, status_monitor, only_spike=False)
    
    if not reference_output_path or not os.path.exists(reference_output_path):
        logging.error("Failed to generate reference and profiling output of original version. Aborting.")
        return

    original_prof5_pattern = os.path.join(execution_config["outputs_dir"], f"*{original_hash}*.prof5")
    possible_original_files = glob.glob(original_prof5_pattern)
    
    original_energy = 1.0
    if possible_original_files:
        try:
            with open(possible_original_files[0], 'r') as f:
                original_energy = float(f.read().strip())
        except Exception as e:
             logging.error(f"Error reading original energy: {e}")

    logging.info(f"Original Energy (Reference): {original_energy}")

    root.status = 'COMPLETED'
    root.error = 0.0
    root.variant_hash = original_hash
    root.energy = original_energy
    root.cost = (1 - args.alpha) * 1.0 
    add_executed_variant(original_hash, execution_config["executed_variants_file"], lock=db_lock)
    
    queue = deque(root.children)
    level = 1
    
    while queue:
        level_size = len(queue)
        logging.info(f"--- Processing Level {level} ({level_size} nodes) ---")
        
        nodes_this_level = [queue.popleft() for _ in range(level_size)]
        max_workers = max(1, os.cpu_count() - 1) if args.workers == 0 else args.workers
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            full_config = {'base_config': execution_config, 'pruning_config': pruning_config}
            futures = {
                executor.submit(process_node, node, app_module, full_config, args.threshold, reference_output_path, status_monitor, db_lock, original_energy, args.alpha): node 
                for node in nodes_this_level
            }

            for future in as_completed(futures):
                node_from_future = futures[future] 
                try:
                    processed_node = future.result()
                    if processed_node.status == 'COMPLETED':
                        for child in processed_node.children:
                            if child.status == 'PENDING':
                                queue.append(child)
                except Exception as e:
                    logging.error(f"Catastrophic error processing node {node_from_future.name}: {e}", exc_info=True)
                    node_from_future.status = 'FAILED_UNEXPECTEDLY'
                    prune_branch(node_from_future)

        level += 1

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    tree_report_path = os.path.join(execution_config["logs_dir"], f"pruning_tree_{args.app}_{timestamp}.txt")
    save_tree_to_file(root, tree_report_path)
    
    tree_dot_path = os.path.join(execution_config["logs_dir"], f"pruning_tree_{args.app}_{timestamp}.dot")
    save_tree_to_dot(root, tree_dot_path)
    logging.info(f"Pruning execution completed. Graph: {tree_dot_path}")


def main():
    """
    Main entry point for PaCA execution.
    
    Parses command-line arguments, validates dependencies, sets up execution
    workspace, and dispatches to either Brute Force or Tree Pruning mode.
    
    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    os.environ["PATH"] = f"/opt/riscv/bin:{os.environ['PATH']}"

    parser = argparse.ArgumentParser(description='Approximate variant simulator')
    parser.add_argument('--app', type=str, default='kinematics', help=f'Application type. Options: {", ".join(AVAILABLE_APPS.keys())}')
    parser.add_argument('--workers', type=int, default=0, help='Number of workers. 0 to use CPU count - 1')
    parser.add_argument('--threshold', type=float, default=0.05, help='Maximum cost threshold allowed to avoid pruning.')
    parser.add_argument('--alpha', type=float, default=1.0, help='Weight of Error in cost heuristic (0.0 to 1.0). Energy will be (1 - alpha).')
    parser.add_argument('--container', type=str, default=None, help='Docker container ID for remote execution. If not provided, uses config_base.py value.')

    # Mutually exclusive execution mode group
    execution_mode_group = parser.add_mutually_exclusive_group(required=True)
    execution_mode_group.add_argument('--forcabruta', action='store_true', help='Execute in brute force mode (previous default).')
    execution_mode_group.add_argument('--arvorePoda', action='store_true', help='Execute in tree pruning mode with variant control and rules.')
    
    args = parser.parse_args()
    
    # Docker Orchestration Mode - use config if --container not specified
    container_id = args.container if args.container else BASE_CONFIG.get("docker_container_id")
    
    # Skip Docker mode if we're already inside the container
    # Check by looking for marker file or environment variable
    if os.path.exists("/.dockerenv") or os.environ.get("PACA_IN_CONTAINER"):
        container_id = None
    
    if container_id:
        from utils.docker_orchestrator import run_simulation_in_container
        logging.info(f"Running in Docker mode with container: {container_id}")
        
        success = run_simulation_in_container(
            container_id=container_id,
            app_name=args.app,
            execution_mode="forcabruta" if args.forcabruta else "arvorePoda",
            workers=args.workers,
            threshold=args.threshold,
            alpha=args.alpha,
            project_root=os.path.dirname(os.path.abspath(__file__)) + "/..",
            sync_results=BASE_CONFIG.get("sync_from_container_after_run", True)
        )
        return 0 if success else 1
    
    if not check_dependencies():
        sys.stderr.write("Missing dependencies. Aborting execution.\n")
        return 1
    
    execution_mode = "forcabruta" if args.forcabruta else "arvorepoda"
    execution_config = create_execution_workspace(args.app, execution_mode, BASE_CONFIG)

    setup_logging(os.path.join(execution_config["logs_dir"], "execucao.log"))

    logging.info(f"=== NEW EXECUTION STARTED ===")
    logging.info(f"Application: {args.app}")
    logging.info(f"Mode: {execution_mode}")
    
    if args.arvorePoda:
        logging.info(f"Cost Threshold: {args.threshold}")
        logging.info(f"Alpha (Error Weight in Heuristic): {args.alpha}")

    import importlib
    app_module_name = AVAILABLE_APPS[args.app]
    app_module = importlib.import_module(app_module_name)

    if hasattr(app_module, f"{args.app.upper()}_CONFIG"):
        execution_config.update(getattr(app_module, f"{args.app.upper()}_CONFIG"))

    app_module = setup_environment(args.app, execution_config)
    db_lock = threading.Lock()
    status_monitor = VariantStatusMonitor()

    # Brute Force Mode Block
    if args.forcabruta:
        logging.info("Executing in Brute Force mode...")
        variants_to_simulate, _ = app_module.find_variants_to_simulate(execution_config)
        
        checkpoint_exists = os.path.exists(execution_config["checkpoint_file"])
        if checkpoint_exists:
            processed_variants_set, processed_count, total_count = load_checkpoint(execution_config)
            resume = input(f"Found checkpoint with {processed_count}/{total_count} processed variants. Continue? (s/n): ")
            if resume.lower() in ('s', 'sim', 'y', 'yes'):
                variants_to_simulate = [(f, h) for f, h in variants_to_simulate if h not in processed_variants_set]
            else:
                processed_variants_set = set()
        else:
            processed_variants_set = set()
        
        status_monitor.start()
        start_time = datetime.now()
        
        if variants_to_simulate:
            successful_variants = 0
            failed_variants = 0
            max_workers = args.workers if args.workers > 0 else max(1, os.cpu_count() - 1)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                for file, variant_hash in variants_to_simulate:
                    futures[executor.submit(
                        app_module.simulate_variant, 
                        file, 
                        variant_hash, 
                        execution_config, 
                        status_monitor
                    )] = (file, variant_hash)
                
                for future in as_completed(futures):
                    file, variant_hash = futures[future]
                    try:
                        result, _ = future.result() 
                        if result:
                            successful_variants += 1
                            add_executed_variant(variant_hash, execution_config["executed_variants_file"], lock=db_lock)
                            
                            # Logic to identify original file and save modified lines
                            if hasattr(app_module, "KMEANS_CONFIG"):
                                original_source_file = app_module.KMEANS_CONFIG["original_file"]
                            elif hasattr(app_module, "JMEINT_CONFIG"):
                                original_source_file = app_module.JMEINT_CONFIG["tritri_source_file"]
                            elif hasattr(app_module, "FFT_CONFIG"):
                                original_source_file = app_module.FFT_CONFIG["fourier_source_file"]
                            elif hasattr(app_module, "SOBEL_CONFIG"):
                                original_source_file = app_module.SOBEL_CONFIG["sobel_source_file"]
                            else:
                                original_source_file = execution_config.get("original_file", file)

                            save_modified_lines_for_bruteforce(file, original_source_file, variant_hash, app_module, execution_config)
                        else:
                            failed_variants += 1
                            add_failed_variant(variant_hash, "execution_failure", execution_config["failed_variants_file"], lock=db_lock)
                            if hasattr(app_module, 'cleanup_variant_files'):
                                app_module.cleanup_variant_files(variant_hash, execution_config, preserve_logs=True)
                    except Exception as e:
                        failed_variants += 1
                        add_failed_variant(variant_hash, f"exception:{str(e)}", execution_config["failed_variants_file"], lock=db_lock)
                        if hasattr(app_module, 'cleanup_variant_files'):
                            app_module.cleanup_variant_files(variant_hash, execution_config, preserve_logs=True)
                    
                    processed_variants_set.add(variant_hash)
                    if len(processed_variants_set) % 5 == 0:
                        save_checkpoint(len(processed_variants_set), len(variants_to_simulate), 
                                       processed_variants_set, execution_config)
            
            end_time = datetime.now()
            execution_duration = (end_time - start_time).total_seconds()
            report_data = {
                "execution_start": start_time.isoformat(),
                "execution_end": end_time.isoformat(),
                "total_duration_seconds": execution_duration,
                "successful_variants": successful_variants,
                "failed_variants": failed_variants,
                "workers_used": max_workers,
                "app_name": args.app,
                "execution_mode": execution_mode,
                "workspace": execution_config["workspace_path"]
            }
            generate_report(report_data, execution_config)
            status_monitor.stop()
            return 0 if failed_variants == 0 else 1
        else:
            status_monitor.stop()
            return 0

    elif args.arvorePoda:
        if not hasattr(app_module, 'get_pruning_config'):
             logging.error(f"Error: Application '{args.app}' does not support tree pruning mode.")
             return 1
        
        status_monitor.start()
        run_tree_pruning_mode(app_module, execution_config, status_monitor, args, db_lock)
        status_monitor.stop()
        return 0
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
