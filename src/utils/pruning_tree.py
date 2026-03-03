"""
Tree Pruning Module for PaCA

This module implements a tree-based exploration strategy for approximate variants.
The tree represents all possible combinations of approximated operations, where:
- Root node: Original (non-approximated) code
- Each level: Adds one more approximated operation
- Branches: Different combinations of operations to approximate

The pruning algorithm uses heuristic cost functions to eliminate unpromising
branches early, dramatically reducing the search space.

Author: PaCA Development Team
License: Academic - All Rights Reserved
"""

from itertools import combinations
from typing import List, Tuple, Optional
from anytree import Node, RenderTree


class VariantNode(Node):
    """
    Represents a node in the variant exploration tree.
    
    Each node corresponds to a specific combination of approximated operations.
    The tree is built level-by-level, where each level adds one more operation.
    
    Attributes:
        modified_lines: Tuple of line indices that are approximated in this variant
        status: Current state (PENDING, SIMULATING, COMPLETED, PRUNED, FAILED)
        error: Computed error relative to reference
        variant_hash: Unique identifier for this variant
        energy: Energy consumption (from Prof5)
        cost: Heuristic cost (weighted error + energy)
    """
    def __init__(
        self, 
        name: str, 
        modified_lines: Optional[List[int]] = None, 
        parent: Optional['VariantNode'] = None, 
        status: str = 'PENDING', 
        error: Optional[float] = None, 
        variant_hash: Optional[str] = None, 
        energy: Optional[float] = None, 
        cost: Optional[float] = None
    ):
        super().__init__(name, parent)
        self.modified_lines = tuple(sorted(modified_lines)) if modified_lines is not None else tuple()
        self.status = status  # PENDING, SIMULATING, COMPLETED, PRUNED, FAILED
        self.error = error
        self.variant_hash = variant_hash
        self.energy = energy  # Energy/time from profiling
        self.cost = cost      # Heuristic cost (error weight + energy weight)


def build_variant_tree(modifiable_lines: List[int]) -> VariantNode:
    """
    Builds the complete variant tree from a list of modifiable line numbers.
    
    The tree structure:
    - Level 0 (root): No modifications (original code)
    - Level 1: Single modifications (n nodes)
    - Level 2: Two modifications (n*(n-1)/2 nodes)
    - Level n: All modifications (1 node)
    
    Args:
        modifiable_lines: List of line numbers that can be approximated
        
    Returns:
        VariantNode: Root node of the constructed tree
    """
    root = VariantNode("original", modified_lines=[])
    nodes = {(): root}

    # Use sorted tuples as keys to ensure combinations like (1,2) and (2,1) are treated identically
    for r in range(1, len(modifiable_lines) + 1):
        for combo in combinations(modifiable_lines, r):
            combo = tuple(sorted(combo))
            parent_combo = combo[:-1]  # Parent is combination with one less element
            parent_node = nodes.get(parent_combo)
            
            if parent_node:
                node_name = "mod_" + "_".join(map(str, combo))
                node = VariantNode(node_name, modified_lines=list(combo), parent=parent_node)
                nodes[combo] = node
    return root


def prune_branch(node: VariantNode) -> None:
    """
    Prunes a node and all its descendants, marking them to not be executed.
    
    This is used when a variant exceeds the cost threshold - all its children
    (which add more approximations) will also exceed the threshold.
    
    Args:
        node: The node to prune (along with all descendants)
    """
    if node.status not in ['COMPLETED', 'FAILED']:
        node.status = 'PRUNED'
    for descendant in node.descendants:
        descendant.status = 'PRUNED'


def save_tree_to_file(root: VariantNode, filepath: str) -> None:
    """
    Saves the tree structure and status to a text file for visualization.
    
    Output format shows each node with its status, error, energy, cost, and hash.
    
    Args:
        root: Root node of the tree
        filepath: Path to output file
    """
    with open(filepath, 'w') as f:
        for pre, _, node in RenderTree(root):
            details_list = [f"status={node.status}"]
            
            if node.error is not None:
                details_list.append(f"error={node.error:.4f}")
            if getattr(node, 'energy', None) is not None and node.energy != float('inf'):
                details_list.append(f"energy={node.energy:.4f}")
            if getattr(node, 'cost', None) is not None:
                details_list.append(f"cost={node.cost:.4f}")
                
            details = ", ".join(details_list)

            # Hash safety check
            if node.variant_hash and len(node.variant_hash) >= 8:
                hash_info = f", hash={node.variant_hash[:8]}"
            elif node.variant_hash:
                hash_info = f", hash={node.variant_hash}"
            else:
                hash_info = ""
                
            f.write(f"{pre}{node.name} [{details}{hash_info}]\n")


def save_tree_to_dot(root: VariantNode, filepath: str) -> None:
    """
    Saves the tree to a Graphviz DOT file for visualization.
    
    Nodes are colored by status:
    - lightgreen: COMPLETED (accepted variant)
    - lightcoral: PRUNED (rejected by heuristic)
    - orangered: FAILED (execution error)
    - lightblue: PENDING (not yet processed)
    - gray: Other states
    
    Args:
        root: Root node of the tree
        filepath: Path to output .dot file
    """
    from anytree.exporter import DotExporter

    def nodeattrfunc(node: VariantNode) -> str:
        # Use modified lines list for label, or 'original' for root
        if node.is_root:
            node_id_str = "original"
        else:
            # Convert tuple of modified lines to list string format
            node_id_str = str(list(node.modified_lines))

        label = f"{node_id_str}\\nStatus: {node.status}"
        if node.error is not None:
            label += f"\\nError: {node.error:.4f}"
        if getattr(node, 'cost', None) is not None:
            label += f"\\nCost: {node.cost:.4f}"
        
        color = {
            'COMPLETED': 'lightgreen',
            'PRUNED': 'lightcoral',
            'FAILED': 'orangered',
            'PENDING': 'lightblue'
        }.get(node.status, 'gray')
        
        return f'label="{label}", style=filled, fillcolor={color}'

    exporter = DotExporter(root, nodeattrfunc=nodeattrfunc)
    exporter.to_dotfile(filepath)
