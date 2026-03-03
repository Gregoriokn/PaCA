"""
Docker Orchestrator Module for PaCA

This module provides automatic Docker container orchestration for running
simulations and compilations without manual file copying.

Usage:
    1. Set CONTAINER_ID in config or pass as argument
    2. Run: python src/run.py --app fft --forcabruta
    3. The orchestrator will:
       - Copy source files to container (always fresh)
       - Execute the simulation
       - Copy results back to host

Features:
    - Auto-detect optimal worker count for container
    - Always sync files before execution (handles annotation changes)
    - Configurable via config_base.py

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

import os
import sys
import shutil
import logging
import json
import subprocess
from typing import Optional, Tuple, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class DockerOrchestrator:
    """
    Manages Docker container operations for PaCA.
    
    This class handles:
    - Connection to running containers
    - File synchronization (host <-> container) - always fresh
    - Auto-detection of optimal worker count
    - Command execution inside container
    - Result retrieval
    """
    
    def __init__(self, container_id: str, workspace_path: str = "/workspace"):
        """
        Initialize Docker orchestrator.
        
        Args:
            container_id: Docker container ID or name
            workspace_path: Path inside container where files will be placed
        """
        self.container_id = container_id
        self.workspace_path = workspace_path
        self._client = None
        self._container = None
        self._max_workers = None
    
    def connect(self) -> bool:
        """
        Connect to the Docker container.
        
        Returns:
            bool: True if connection successful
        """
        try:
            import docker
            self._client = docker.from_env()
            self._container = self._client.containers.get(self.container_id)
            
            # Check if container is running
            if self._container.status != 'running':
                logger.error(f"Container {self.container_id} is not running (status: {self._container.status})")
                return False
            
            logger.info(f"Connected to container: {self.container_id}")
            return True
            
        except ImportError as ie:
            logger.error(f"Docker SDK not installed. Run: pip install docker. Error: {ie}")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to container: {e}")
            return False
    
    def detect_max_workers(self) -> int:
        """
        Automatically detect the maximum number of workers the container can handle.
        
        Detection method:
        1. Get container CPU limit
        2. Get container memory info
        3. Check available memory
        4. Calculate optimal workers
        
        Returns:
            int: Recommended number of workers
        """
        if self._max_workers is not None:
            return self._max_workers
        
        try:
            # Get container info
            container_info = self._container.stats(stream=False)
            
            # Get CPU count from container
            # Use online CPUs or fallback to host CPU count
            cpu_count = container_info.get('online_cpus', os.cpu_count() or 2)
            
            # Get memory limit
            memory_limit = container_info.get('memory_limit', 0)
            memory_usage = container_info.get('memory_usage', 0)
            
            # Calculate available memory in GB
            if memory_limit > 0:
                available_memory_gb = (memory_limit - memory_usage) / (1024**3)
            else:
                available_memory_gb = 8  # Assume 8GB if no limit
            
            # Estimate workers based on resources
            # Each worker needs ~512MB for RISC-V simulation
            memory_based_workers = max(1, int(available_memory_gb / 0.5))
            
            # CPU-based workers
            cpu_based_workers = max(1, cpu_count - 1)  # Leave 1 for host
            
            # Use the lower of the two, with a reasonable max
            recommended_workers = min(memory_based_workers, cpu_based_workers, 8)
            
            self._max_workers = max(1, recommended_workers)
            logger.info(f"Detected max workers: {self._max_workers} (CPUs: {cpu_count}, Memory: {available_memory_gb:.1f}GB available)")
            
            return self._max_workers
            
        except Exception as e:
            logger.warning(f"Failed to detect workers, using default: {e}")
            self._max_workers = 2
            return self._max_workers
    
    def sync_to_container(self, host_path: str, container_path: Optional[str] = None) -> bool:
        """
        Copy files from host to container.
        ALWAYS syncs to ensure annotation changes are reflected.
        
        Args:
            host_path: Path to file/directory on host
            container_path: Destination path in container (default: workspace_path)
            
        Returns:
            bool: True if sync successful
        """
        if container_path is None:
            container_path = self.workspace_path
        
        try:
            # Ensure container directory exists
            self._container.exec_run(f"mkdir -p {container_path}")
            
            # Copy files using tar stream
            os_path = Path(host_path)
            
            if not os_path.exists():
                logger.warning(f"Host path does not exist: {host_path}")
                return False
            
            # For directories, use tar stream
            if os_path.is_dir():
                import tarfile
                import io
                
                # Create tar in memory
                tar_buffer = io.BytesIO()
                with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                    tar.add(host_path, arcname=os_path.name)
                tar_buffer.seek(0)
                
                # Copy via container's stdin
                self._container.put_archive(
                    container_path,
                    tar_buffer.getvalue()
                )
                logger.info(f"Synced directory to container: {host_path} -> {container_path}")
            else:
                # For single file, use put_archive with single file
                import tarfile
                import io
                
                tar_buffer = io.BytesIO()
                with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                    tar.add(host_path, arcname=os_path.name)
                tar_buffer.seek(0)
                
                self._container.put_archive(
                    container_path,
                    tar_buffer.getvalue()
                )
                logger.info(f"Synced file to container: {host_path} -> {container_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to sync to container: {e}")
            return False
    
    def sync_from_container(self, container_path: str, host_path: str) -> bool:
        """
        Copy files from container to host using docker cp command.
        
        Args:
            container_path: Path in container
            host_path: Destination path on host
            
        Returns:
            bool: True if sync successful
        """
        try:
            # Use docker cp command directly - more reliable than get_archive
            cmd = ["docker", "cp", f"{self.container_id}:{container_path}", host_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"docker cp failed: {result.stderr}")
                return False
            
            logger.info(f"Synced from container: {container_path} -> {host_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to sync from container: {e}")
            return False
    
    def execute_command(self, command: str, working_dir: Optional[str] = None, env_vars: Optional[dict] = None) -> Tuple[int, str, str]:
        """
        Execute a command inside the container.
        
        Args:
            command: Command to execute
            working_dir: Working directory (default: workspace_path)
            env_vars: Additional environment variables to set
            
        Returns:
            tuple: (exit_code, stdout, stderr)
        """
        if working_dir is None:
            working_dir = self.workspace_path
        
        # Build environment exports
        env_exports = "export PATH=/opt/riscv/bin:$PATH"
        if env_vars:
            for key, value in env_vars.items():
                env_exports += f" && export {key}={value}"
        
        try:
            # Use exec_run for command execution - add RISC-V to PATH
            full_command = f"bash -c '{env_exports} && cd {working_dir} && {command}'"
            logger.info(f"Executing in container: {full_command[:100]}...")
            result = self._container.exec_run(
                full_command,
                demux=True  # Returns stdout/stderr separately
            )
            
            stdout, stderr = result.output
            
            # Decode bytes to string
            stdout_str = stdout.decode('utf-8') if stdout else ""
            stderr_str = stderr.decode('utf-8') if stderr else ""
            
            return result.exit_code, stdout_str, stderr_str
            
        except Exception as e:
            logger.error(f"Failed to execute command: {e}")
            return -1, "", str(e)
    
    def execute_python(self, script_path: str, args: str = "", env_vars: Optional[dict] = None) -> Tuple[int, str, str]:
        """
        Execute a Python script inside the container.
        
        Args:
            script_path: Path to Python script (relative to workspace)
            args: Command-line arguments
            env_vars: Environment variables
            
        Returns:
            tuple: (exit_code, stdout, stderr)
        """
        command = f"python3 {script_path} {args}"
        return self.execute_command(command, env_vars=env_vars)
    
    def is_riscv_available(self) -> bool:
        """
        Check if RISC-V toolchain is available in container.
        
        Returns:
            bool: True if riscv32-unknown-elf-g++ is found
        """
        exit_code, stdout, stderr = self.execute_command("which riscv32-unknown-elf-g++")
        return exit_code == 0
    
    def get_container_info(self) -> Dict[str, Any]:
        """
        Get container information.
        
        Returns:
            dict: Container details
        """
        return {
            "id": self._container.id,
            "name": self._container.name,
            "status": self._container.status,
            "image": self._container.image.tags[0] if self._container.image.tags else self._container.image.short_id,
            "max_workers": self.detect_max_workers()
        }


def create_orchestrator(container_id: str) -> Optional[DockerOrchestrator]:
    """
    Factory function to create a Docker orchestrator.
    
    Args:
        container_id: Docker container ID or name
        
    Returns:
        DockerOrchestrator instance or None if connection fails
    """
    orchestrator = DockerOrchestrator(container_id)
    
    if orchestrator.connect():
        # Verify RISC-V toolchain
        if not orchestrator.is_riscv_available():
            logger.warning("RISC-V toolchain not found in container!")
        
        # Auto-detect workers
        orchestrator.detect_max_workers()
        return orchestrator
    
    return None


def sync_project_to_container(orchestrator: DockerOrchestrator, project_root: str, force: bool = True) -> bool:
    """
    Sync entire project to container.
    
    ALWAYS syncs (force=True) to ensure annotation changes are always reflected.
    
    Args:
        orchestrator: DockerOrchestrator instance
        project_root: Root directory of PaCA project
        force: If True, always sync (default: True)
        
    Returns:
        bool: True if sync successful
    """
    import tarfile
    import io
    
    project_root = os.path.abspath(project_root)
    
    # Always ensure workspace exists in container (force fresh sync)
    orchestrator._container.exec_run("mkdir -p /workspace")
    
    # Change to project root so we don't include parent dirs
    original_cwd = os.getcwd()
    try:
        os.chdir(project_root)
        
        # Create tar with only top-level items (src, data, etc.)
        # This ensures annotation changes are always reflected
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            for item in ['src', 'data', 'requirements.txt']:
                item_path = os.path.join(project_root, item)
                if os.path.exists(item_path):
                    tar.add(item_path, arcname=item)
        
        tar_buffer.seek(0)
        
        # Copy to container
        orchestrator._container.put_archive('/workspace', tar_buffer.getvalue())
        logger.info(f"Synced project to container: {project_root} -> /workspace (always fresh)")
        
    finally:
        os.chdir(original_cwd)
    
    return True


def run_simulation_in_container(
    container_id: str,
    app_name: str,
    execution_mode: str,
    workers: int = 0,  # 0 = auto-detect
    threshold: float = 0.05,
    alpha: float = 1.0,
    project_root: str = ".",
    sync_results: bool = True
) -> bool:
    """
    High-level function to run simulation entirely in container.
    
    This function:
    1. Connects to container
    2. ALWAYS syncs project files (to reflect annotation changes)
    3. Auto-detects optimal worker count
    4. Runs the simulation
    5. Syncs results back
    
    Args:
        container_id: Docker container ID
        app_name: Application name (fft, kmeans, etc.)
        execution_mode: 'forcabruta' or 'arvorePoda'
        workers: Number of workers (0 = auto-detect)
        threshold: Cost threshold for pruning
        alpha: Error weight
        project_root: Path to PaCA project
        sync_results: Whether to copy results back to host
        
    Returns:
        bool: True if simulation completed successfully
    """
    project_root = os.path.abspath(project_root)
    
    logger.info(f"Connecting to container: {container_id}")
    orchestrator = create_orchestrator(container_id)
    
    if orchestrator is None:
        logger.error("Failed to connect to container")
        return False
    
    # Show container info
    info = orchestrator.get_container_info()
    logger.info(f"Container: {info['name']} ({info['status']}) - Image: {info['image']}")
    logger.info(f"Max workers detected: {info['max_workers']}")
    
    # Auto-detect workers if not specified
    if workers == 0:
        workers = info['max_workers']
        logger.info(f"Using auto-detected workers: {workers}")
    
    # ALWAYS sync project to container (to reflect annotation changes)
    logger.info("Syncing project files to container (always fresh)...")
    if not sync_project_to_container(orchestrator, project_root, force=True):
        logger.error("Failed to sync project files")
        return False
    
    # Build command
    cmd_parts = [
        "python3 src/run.py",
        f"--app {app_name}",
        f"--workers {workers}",
    ]
    
    if execution_mode == "forcabruta":
        cmd_parts.append("--forcabruta")
    else:
        cmd_parts.append("--arvorePoda")
        cmd_parts.append(f"--threshold {threshold}")
        cmd_parts.append(f"--alpha {alpha}")
    
    command = " ".join(cmd_parts)
    logger.info(f"Executing: {command}")
    
    # Execute in container - set marker so run.py knows it's inside container
    exit_code, stdout, stderr = orchestrator.execute_python("src/run.py", 
        f"--app {app_name} --workers {workers} --{execution_mode} " +
        (f"--threshold {threshold} --alpha {alpha}" if execution_mode == "arvorePoda" else ""),
        env_vars={"PACA_IN_CONTAINER": "1"})
    
    print("\n=== STDOUT ===")
    print(stdout)
    
    if stderr:
        print("\n=== STDERR ===")
        print(stderr)
    
    # Sync results back to host
    if sync_results and exit_code == 0:
        logger.info("Syncing results from container to host...")
        
        storage_path = os.path.join(project_root, "storage")
        os.makedirs(storage_path, exist_ok=True)
        
        # Get the latest execution directory
        exit_code_sync, stdout_sync, stderr_sync = orchestrator.execute_command(
            "ls -t /workspace/storage/executions/ | head -1"
        )
        
        if exit_code_sync == 0 and stdout_sync.strip():
            latest_exec = stdout_sync.strip()
            logger.info(f"Found latest execution: {latest_exec}")
            
            # Sync the execution folder
            container_exec_path = f"/workspace/storage/executions/{latest_exec}"
            host_exec_path = os.path.join(storage_path, "executions", latest_exec)
            
            if orchestrator.sync_from_container(container_exec_path, host_exec_path):
                logger.info(f"Results copied to: {host_exec_path}")
                print(f"\n✅ Results saved to: {host_exec_path}")
            else:
                logger.warning("Failed to sync results from container")
        else:
            logger.warning("No execution directory found to sync")
    
    if exit_code == 0:
        logger.info("Simulation completed successfully!")
    else:
        logger.error(f"Simulation failed with exit code: {exit_code}")
    
    return exit_code == 0


def interactive_mode():
    """
    Interactive mode - asks for container ID and runs simulation.
    """
    import getpass
    
    print("=" * 50)
    print("PaCA Docker Orchestrator - Interactive Mode")
    print("=" * 50)
    
    # Get container ID
    container_id = input("Container ID/Name: ").strip()
    if not container_id:
        print("Error: Container ID required")
        return
    
    # Get app
    print("\nAvailable apps: fft, kmeans, sobel, blackscholes, inversek2j, jmeint")
    app_name = input("Application [fft]: ").strip() or "fft"
    
    # Get mode
    print("\nExecution modes: forcabruta, arvorePoda")
    mode = input("Mode [forcabruta]: ").strip() or "forcabruta"
    
    # Workers - auto-detect
    workers_input = input("Workers (0 for auto-detect) [0]: ").strip() or "0"
    workers = int(workers_input)
    
    # Get threshold/alpha if tree pruning
    threshold = 0.05
    alpha = 1.0
    
    if mode == "arvorePoda":
        threshold = float(input("Threshold [0.05]: ").strip() or "0.05")
        alpha = float(input("Alpha [1.0]: ").strip() or "1.0")
    
    # Run
    success = run_simulation_in_container(
        container_id=container_id,
        app_name=app_name,
        execution_mode=mode,
        workers=workers,
        threshold=threshold,
        alpha=alpha
    )
    
    if success:
        print("\n✅ Simulation completed!")
    else:
        print("\n❌ Simulation failed!")


if __name__ == "__main__":
    # Run in interactive mode
    logging.basicConfig(level=logging.INFO)
    interactive_mode()
