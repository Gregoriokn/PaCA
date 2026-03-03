"""
Variant Generator Module for PaCA

This module generates approximate code variants by applying combinatorial
transformations to identified modifiable lines. It supports two strategies:
- "all": Generate all possible combinations (2^n variants)
- "one_hot": Generate only single modifications (n variants)

The generator skips already-executed variants to enable resumability.

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

import os
import argparse
from itertools import combinations
from transformations import apply_transformation
from database.variant_tracker import load_executed_variants
from hash_utils import gerar_hash_codigo_logico
from typing import List, Tuple, Optional


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
    """
    Generates variants of the code by replacing operations on modifiable lines.
    
    This function applies combinatorial transformations to create all possible
    approximate variants based on the identified modifiable lines.
    
    Args:
        lines: Source code lines (from code_parser)
        modifiable_lines: List of line indices that can be modified
        physical_to_logical: Mapping from physical to logical line numbers
        operation_map: Dictionary mapping operators to approximate versions
                      e.g., {'*': 'FMULX', '+': 'FADDX'}
        output_folder: Directory to save generated variant files
        file_name: Base name for output files
        executed_file: Path to file tracking already executed variants
        limit: Maximum number of variants to generate (safety limit)
        strategy: Generation strategy - "all" (combinatorial) or "one_hot" (single)
        
    Returns:
        List of tuples: (output_file_path, variant_hash)
    """
    if not os.path.exists(output_folder):
        try:
            os.makedirs(output_folder)
            print(f"Output folder created: {output_folder}")
        except OSError as e:
            print(f"Error creating folder: {e}")

    # Load already executed variants to avoid duplicates
    executed_variants = load_executed_variants(executed_file)
    
    modified_files = []
    skipped = 0
    generated_count = 0
    
    # Strategy Logic
    if strategy == "one_hot":
        # Only 1-element combinations (generates X variants where X = modifiable lines)
        range_comb = range(1, 2)
    else:
        # Brute Force / All: Combinations of 1 to N elements (generates 2^X variants)
        range_comb = range(1, len(modifiable_lines) + 1)

    print(f"Starting generation. Strategy: {strategy}, Modifiable Lines: {len(modifiable_lines)}")

    # Main generation loop
    for r in range_comb:
        # Stop outer loop if limit reached
        if limit and generated_count >= limit:
            break

        for combination in combinations(modifiable_lines, r):
            # Global limit check inside inner loop
            if limit is not None and generated_count >= int(limit):
                print(f"Variant limit reached ({limit}). Stopping generation.")
                return modified_files

            modified_lines = lines.copy()  # Fresh copy of original lines
            
            # Apply substitutions only to selected lines in this combination
            for idx in combination:
                modified_lines[idx] = apply_transformation(modified_lines[idx], operation_map)
            
            # Generate logical hash
            codigo_hash = gerar_hash_codigo_logico(modified_lines, physical_to_logical)
            
            # Check if variant was already executed
            if codigo_hash in executed_variants:
                skipped += 1
                if skipped % 500 == 0:
                    print(f"Variant already executed (skip): {codigo_hash[:8]}")
                continue
                
            # Output filename with Hash
            nome_base, extensao = os.path.splitext(file_name)
            output_file = f"{nome_base}_{codigo_hash}{extensao}"
            output_path = os.path.join(output_folder, output_file)
            
            # Save file
            try:
                with open(output_path, 'w', newline='') as f:
                    f.writelines(modified_lines)
                
                modified_files.append((output_path, codigo_hash))
                generated_count += 1
                
                if generated_count % 500 == 0:
                    print(f"Generated {generated_count} variants so far...")
            except Exception as e:
                print(f"Error saving file {output_file}: {e}")
    
    print(f"Generation completed.")
    print(f"Total new variants generated: {len(modified_files)}")
    print(f"Total skipped variants (already existing): {skipped}")
    
    return modified_files
