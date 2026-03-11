"""
Base Configuration for PaCA

Shared configuration settings for all applications.
Contains paths, Docker settings, and default parameters.

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

BASE_CONFIG = {
    # Directories
    "executables_dir": "storage/executable",
    "outputs_dir": "storage/output",
    "logs_dir": "storage/logs",  
    "input_dir": "storage/variantes",
    "prof5_results_dir": "storage/prof5_results",
    "dump_dir": "storage/dump",
    
    # Configuration files
    "approx_file": "data/reference/approx.h",
    "executed_variants_file": "data/reference/executados.txt",
    "failed_variants_file": "data/reference/falhas.txt",
    
    # Prof5 settings
    "prof5_model": "data/models/APPROX_1.json",
    
    # Docker Orchestration (optional)
    # Set container_id to enable Docker orchestration
    # Example: "3d0403713d454fa9f9906b45a7bc23694f326a623acb04022cb39acf1bea2007"
    # Leave as None to run locally
    "docker_container_id": "5dd5660f6014",
    
    # Docker workspace path (inside container)
    "docker_workspace": "/workspace",
    
    # Sync settings
    "sync_to_container_before_run": True,
    "sync_from_container_after_run": True,  # Copia resultados de volta

    # Dump generation (set to False to save disk space)
    # Dumps are objdump disassembly - useful for debugging but not required for simulation
    "generate_dumps": False,
}
