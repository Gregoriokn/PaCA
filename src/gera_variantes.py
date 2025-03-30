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
        args = parser.parse_args()

        # Atualiza configuração se necessário
        if args.input:
            update_config({"input_file": args.input})
        if args.output:
            update_config({"output_folder": args.output})
        if args.executados:
            update_config({"executed_variants_file": args.executados})
    else:
        # Usa a configuração passada como parâmetro
        update_config(config_override)
    
    # Obtém as configurações atualizadas
    input_file = CONFIG["input_file"]
    output_folder = CONFIG["output_folder"]
    operation_map = CONFIG["operations_map"]
    executed_file = CONFIG["executed_variants_file"]

    print(f"Processando arquivo: {input_file}")
    print(f"Pasta de saída: {output_folder}")
    print(f"Arquivo de controle: {executed_file}")

    lines, modifiable_lines, physical_to_logical = parse_code(input_file)
    print(f"Detectadas {len(modifiable_lines)} linhas modificáveis")
    
    variants = generate_variants(
        lines, modifiable_lines, physical_to_logical, 
        operation_map, output_folder, os.path.basename(input_file), 
        executed_file
    )
    
    print(f"Geração concluída. {len(variants)} variantes geradas.")
    
    return variants


if __name__ == "__main__":
    main()