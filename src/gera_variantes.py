import os
import argparse
from config import CONFIG, update_config
from code_parser import parse_code
from generator import generate_variants

def main(config_override=None):
    # Configurar argumentos da linha de comando apenas se chamado diretamente
    if config_override is None:
        parser = argparse.ArgumentParser(description='Gerador de variantes de código')
        parser.add_argument('--input', type=str, help='Arquivo de entrada (sobrepõe configuração)')
        parser.add_argument('--output', type=str, help='Pasta de saída (sobrepõe configuração)')
        parser.add_argument('--executados', type=str, help='Arquivo de variantes executadas')
        parser.add_argument('--debug', type=str, help='Arquivo de debug para registrar variantes geradas')
        args = parser.parse_args()

        # Atualiza configuração se necessário
        if args.input:
            update_config({"input_file": args.input})
        if args.output:
            update_config({"output_folder": args.output})
        if args.executados:
            update_config({"executed_variants_file": args.executados})
        if args.debug:
            update_config({"debug_file": args.debug})
    else:
        # Usa a configuração passada como parâmetro
        update_config(config_override)
    
    # Obtém as configurações atualizadas
    input_file = CONFIG["input_file"]
    output_folder = CONFIG["output_folder"]
    operation_map = CONFIG["operations_map"]
    executed_file = CONFIG["executed_variants_file"]
    debug_file = CONFIG.get("debug_file", os.path.join(output_folder, "variantes_debug.txt"))

    print(f"Processando arquivo: {input_file}")
    print(f"Pasta de saída: {output_folder}")
    print(f"Arquivo de controle: {executed_file}")
    print(f"Arquivo de debug: {debug_file}")

    lines, modifiable_lines, physical_to_logical = parse_code(input_file)
    print(f"Detectadas {len(modifiable_lines)} linhas modificáveis")
    
    variants = generate_variants(
        lines, modifiable_lines, physical_to_logical, 
        operation_map, output_folder, os.path.basename(input_file), 
        executed_file
    )
    
    # Cria a pasta para os arquivos individuais de linhas modificadas
    linhas_dir = os.path.join("storage", "linhas_modificadas")
    os.makedirs(linhas_dir, exist_ok=True)
    
    # Extrai o nome da aplicação (sem extensão)
    app_name = os.path.splitext(os.path.basename(input_file))[0]
    
    # Gera um arquivo individual para cada variante
    for variant_file, variant_hash in variants:
        # Compara variante com o original para identificar linhas modificadas
        with open(variant_file, 'r') as vf:
            variant_lines = vf.readlines()
        
        # Determina quais linhas foram modificadas
        modified_indices = []
        for idx in modifiable_lines:
            if idx < len(lines) and idx < len(variant_lines):
                if lines[idx].strip() != variant_lines[idx].strip():
                    modified_indices.append(idx)
        
        # Converte índices físicos para lógicos
        logical_modified = [physical_to_logical.get(idx) for idx in modified_indices if idx in physical_to_logical]
        
        # Cria o arquivo individual para esta variante com APENAS as linhas lógicas
        individual_file = os.path.join(linhas_dir, f"{app_name}_linhas_{variant_hash}.txt")
        with open(individual_file, 'w') as f:
            # Escreve apenas os números das linhas lógicas modificadas, uma por linha
            for logical_line in sorted(logical_modified):
                f.write(f"{logical_line}\n")
    
    print(f"Criados {len(variants)} arquivos individuais de linhas modificadas em {linhas_dir}")
    
    # Mantém o arquivo de debug completo com todas as informações
    if variants:
        # Certifique-se de que o diretório exista
        os.makedirs(os.path.dirname(debug_file), exist_ok=True)
        
        with open(debug_file, 'w') as f:
            f.write(f"Arquivo original: {input_file}\n")
            f.write(f"Total de variantes: {len(variants)}\n")
            f.write(f"Linhas modificáveis: {modifiable_lines}\n\n")
            
            for i, (variant_file, variant_hash) in enumerate(variants, 1):
                f.write(f"Variante #{i}\n")
                f.write(f"  Arquivo: {os.path.basename(variant_file)}\n")
                f.write(f"  Hash: {variant_hash}\n")
                
                # Compara variante com o original para identificar linhas modificadas
                with open(variant_file, 'r') as vf:
                    variant_lines = vf.readlines()
                
                modified_indices = []
                for idx in modifiable_lines:
                    if idx < len(lines) and idx < len(variant_lines):
                        if lines[idx].strip() != variant_lines[idx].strip():
                            modified_indices.append(idx)
                
                f.write(f"  Linhas físicas modificadas: {modified_indices}\n")
                logical_modified = [physical_to_logical.get(idx) for idx in modified_indices if idx in physical_to_logical]
                f.write(f"  Linhas lógicas modificadas: {sorted(logical_modified)}\n")
                
                # Adiciona as linhas modificadas com o conteúdo
                for idx in modified_indices:
                    logical_idx = physical_to_logical.get(idx, "N/A")
                    f.write(f"    Linha {idx} (lógica {logical_idx}):\n")
                    f.write(f"      Original: {lines[idx].strip()}\n")
                    f.write(f"      Modificada: {variant_lines[idx].strip()}\n")
                
                f.write("\n" + "-"*60 + "\n\n")
        
        print(f"Arquivo de debug gerado: {debug_file}")
    
    print(f"Geração concluída. {len(variants)} variantes geradas.")
    
    return variants


if __name__ == "__main__":
    main()