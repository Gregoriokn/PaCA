"""
Code Transformation Module for PaCA

This module applies transformations to source code lines by replacing standard
arithmetic operators with approximate operator macros.

Transformations supported:
- '+' -> FADDX (Approximate Floating-Point Add)
- '-' -> FSUBX (Approximate Floating-Point Subtract)
- '*' -> FMULX (Approximate Floating-Point Multiply)

The module handles complex cases like nested expressions and preserves
parentheses correctly to avoid syntax errors.

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

import re
import json
from typing import Dict, List


def apply_transformation(line_content: str, operations_map: Dict[str, str]) -> str:
    """
    Transforms a source code line by replacing operators with approximate macros.
    
    This enhanced version replaces operators with macros (e.g., a + b -> FADDX(a, b))
    and cleans up orphaned parentheses to avoid syntax errors.
    
    Args:
        line_content: The original source code line
        operations_map: Dictionary mapping operators to macro names
                       e.g., {'*': 'FMULX', '+': 'FADDX', '-': 'FSUBX'}
                       
    Returns:
        str: The transformed line with operators replaced by macros
    """
    # Step 1: Sort operators by length (longest first) to prevent '+' matching '++'
    sorted_ops = sorted(operations_map.keys(), key=len, reverse=True)
    ops_pattern = "|".join([re.escape(op) for op in sorted_ops])
    
    # Step 2: Regex pattern for operands
    # Captures: variables, struct members (.), arrays ([]), pointers (->), parentheses and negative numbers
    operand_pattern = r"[\w\.\[\]\->\(\)-]+"
    
    # Complete regex: (Operand1) (Spaces) (Operator) (Spaces) (Operand2)
    pattern = re.compile(rf"({operand_pattern})\s*({ops_pattern})\s*({operand_pattern})")

    def replace_with_macro(match):
        arg1 = match.group(1).strip()
        operator = match.group(2)
        arg2 = match.group(3).strip()
        
        # Critical cleanup: Remove parentheses that parser incorrectly captured
        # This avoids "expected primary-expression before ','" errors
        arg1 = arg1.lstrip('(').rstrip(')')
        arg2 = arg2.lstrip('(').rstrip(')')
        
        macro = operations_map.get(operator, operator)
        return f"{macro}({arg1}, {arg2})"

    # Step 3: Iterative application to handle complex lines like "a + b + c"
    current_line = line_content
    for _ in range(10):  # Safety limit
        new_line = pattern.sub(replace_with_macro, current_line, count=1)
        if new_line == current_line:
            break
        current_line = new_line
    
    return current_line


def detect_operations(original_line: str, modified_line: str, operations_map: Dict[str, str]) -> List[str]:
    """
    Detects which operations were applied to a line by comparing original and modified.
    
    Args:
        original_line: The original source line
        modified_line: The transformed line
        operations_map: Dictionary mapping operators to macro names
                       e.g., {'*': 'FMULX', '+': 'FADDX'}
    
    Returns:
        List of operations applied (e.g., ['FMULX', 'FADDX'])
    """
    detected = []
    
    # Create reverse map: macro -> operator
    reverse_map = {v: k for k, v in operations_map.items()}
    
    # For each macro, check if it appears in modified line
    for macro, operator in reverse_map.items():
        if macro in modified_line:
            # Check if operator exists in original line surrounded by spaces or parens
            # Use regex to match operator with whitespace around it
            pattern = r'\s' + re.escape(operator) + r'\s'
            if re.search(pattern, ' ' + original_line + ' '):
                detected.append(macro)
    
    return detected


def detect_operations_per_line(original_lines: List[str], modified_lines: List[str], 
                               physical_to_logical: Dict[int, int], 
                               operations_map: Dict[str, str]) -> Dict[str, List[str]]:
    """
    Detects operations applied to each modified line.
    
    Args:
        original_lines: List of original source lines
        modified_lines: List of modified source lines
        physical_to_logical: Mapping from physical to logical line numbers
        operations_map: Dictionary mapping operators to macro names
    
    Returns:
        Dictionary mapping line identifiers to operations applied
        Format: {"line_87": ["FMULX"], "line_95": ["FADDX"]}
    """
    operations_per_line = {}
    
    for phys_idx in range(min(len(original_lines), len(modified_lines))):
        orig_line = original_lines[phys_idx]
        mod_line = modified_lines[phys_idx]
        
        if orig_line != mod_line:
            # Line was modified
            ops = detect_operations(orig_line, mod_line, operations_map)
            
            if ops:
                # Use logical line number as key if available, otherwise use physical-1 (annotation line)
                logical_line = physical_to_logical.get(phys_idx)
                if logical_line is not None:
                    line_key = str(logical_line)
                elif (phys_idx - 1) in physical_to_logical:
                    # Line after annotation - use the annotation line's logical mapping
                    line_key = str(physical_to_logical[phys_idx - 1])
                else:
                    # Use physical line as fallback
                    line_key = str(phys_idx)
                operations_per_line[line_key] = ops
    
    return operations_per_line


def save_operations_json(operations_per_line: Dict[str, List[str]], output_path: str) -> None:
    """
    Saves operations per line to a JSON file.
    
    Args:
        operations_per_line: Dictionary mapping line numbers to operations
        output_path: Path to save the JSON file
    """
    # Convert list values to comma-separated strings for JSON
    output_data = {str(k): ",".join(v) for k, v in operations_per_line.items()}
    
    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=2)
