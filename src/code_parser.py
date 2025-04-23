import re

def parse_code(file_path):
    """
    Analisa um arquivo de código-fonte para identificar linhas modificáveis.
    Retorna as linhas do código, as linhas modificáveis e o mapeamento físico para lógico.
    """
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    modifiable_lines = []
    physical_to_logical = {}
    logical_line_count = 0
    
    for i, line in enumerate(lines):
        # Ignora linhas em branco
        if re.match(r'^\s*$', line):
            continue
        
        # Verifica se a linha contém //anotacao: independente de espaços
        if re.match(r'^\s*//anotacao:\s*$', line):
            if i + 1 < len(lines):
                modifiable_lines.append(i + 1)
            continue  # Pula a contagem lógica para as anotações
        
        logical_line_count += 1
        physical_to_logical[i] = logical_line_count
    
    return lines, modifiable_lines, physical_to_logical