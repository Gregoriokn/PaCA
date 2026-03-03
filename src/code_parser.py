"""
Source Code Parser Module for PaCA

This module parses source code files to identify lines that can be approximated.
It uses a simple annotation system where lines prefixed with //anotacao: mark
the subsequent line as modifiable.

The parser builds:
- A list of modifiable line indices (physical line numbers)
- A mapping from physical to logical line numbers (for consistent hashing)

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

import re
import logging
from typing import Tuple, List, Dict


def parse_code(file_path: str) -> Tuple[List[str], List[int], Dict[int, int]]:
    """
    Analyzes a source code file to identify modifiable lines.
    
    The parser looks for lines containing exactly "//anotacao:" (with optional
    whitespace) which mark the following line as approximable.
    
    Args:
        file_path: Path to the source code file to parse
        
    Returns:
        tuple containing:
            - lines: List of all source lines (preserving original content)
            - modifiable_lines: List of indices (int) of lines that can be modified
            - physical_to_logical: Mapping from physical index to logical line number
    """
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return [], [], {}
    
    modifiable_lines = []
    physical_to_logical = {}
    logical_line_count = 0
    
    # Pattern to find annotation lines: //anotacao: or /*anotacao:*/
    # Optionally accepts '\' at end for line continuation in macros
    annotation_pattern = re.compile(r'^\s*(?://anotacao:|/\*anotacao:\*/)\s*(?:\\)?\s*$')
    
    for i, line in enumerate(lines):
        # Skip blank lines for logical line counting
        if re.match(r'^\s*$', line):
            continue
        
        # Check if current line is an annotation
        if annotation_pattern.match(line):
            # The next line (i + 1) is the one that will be modified
            if i + 1 < len(lines):
                modifiable_lines.append(i + 1)
            continue 
        
        # Count logical lines (for metrics and consistent hashing)
        logical_line_count += 1
        physical_to_logical[i] = logical_line_count
    
    # Critical warning if no modifiable lines found
    if not modifiable_lines:
        msg = (
            f"[PARSER WARNING] No modifiable lines found in: {file_path}\n"
            f"HINT: The parser looks for lines containing exactly '//anotacao:' "
            f"immediately before the target code line."
        )
        print(msg)  # Force print to stdout
        logging.warning(msg)
    
    return lines, modifiable_lines, physical_to_logical
