#!/usr/bin/env python3

import os
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Importações gerais
from config_base import BASE_CONFIG
from database.variant_tracker import add_executed_variant, add_failed_variant
from utils.logger import setup_logging, VariantStatusMonitor
from utils.file_utils import ensure_dirs, short_hash, generate_report, save_checkpoint, load_checkpoint

# Dicionário de aplicações disponíveis
AVAILABLE_APPS = {
    "kinematics": "apps.kinematics"
}

def check_dependencies():
    """Verifica se todas as ferramentas necessárias estão disponíveis"""
    import shutil
    
    tools = ["riscv32-unknown-elf-g++", "riscv32-unknown-elf-objdump", "spike"]
    missing = []
    
    for tool in tools:
        if not shutil.which(tool):
            missing.append(tool)
    
    if missing:
        print(f"Ferramentas necessárias não encontradas: {', '.join(missing)}")
        return False
    return True

def setup_environment(app_name):
    """Prepara o ambiente para execução"""
    # Adiciona o diretório bin do RISC-V ao PATH
    os.environ["PATH"] += ":/opt/riscv/bin"
    
    # Verifica se a aplicação existe
    if app_name not in AVAILABLE_APPS:
        print(f"Erro: Aplicação '{app_name}' não encontrada.")
        return False
    
    # Importa dinamicamente o módulo da aplicação
    try:
        app_module = __import__(AVAILABLE_APPS[app_name], fromlist=[''])
    except ImportError as e:
        print(f"Erro: Não foi possível importar o módulo '{AVAILABLE_APPS[app_name]}': {e}")
        return False
    
    # Cria os diretórios necessários
    ensure_dirs(
        BASE_CONFIG["executables_dir"], 
        BASE_CONFIG["outputs_dir"], 
        BASE_CONFIG["input_dir"],
        BASE_CONFIG["logs_dir"],
        BASE_CONFIG["prof5_results_dir"],
        BASE_CONFIG["dump_dir"]
    )
    
    # Gera as variantes de código específicas da aplicação
    app_module.generate_variants(BASE_CONFIG)
    
    # Prepara ambiente específico da aplicação
    if not app_module.prepare_environment(BASE_CONFIG):
        print(f"Erro: Falha ao preparar ambiente para '{app_name}'")
        return False
    
    return app_module

def main():
    """Função principal do programa"""
    # Configuração da linha de comando
    parser = argparse.ArgumentParser(description='Simulador de variantes aproximadas')
    parser.add_argument('--app', type=str, default='kinematics',
                      help=f'Tipo de aplicação. Opções: {", ".join(AVAILABLE_APPS.keys())}')
    # Adicione uma opção para controlar o paralelismo
    parser.add_argument('--workers', type=int, default=0,
                      help='Número de workers. 0 para usar CPU count - 1')
    args = parser.parse_args()
    
    # Verifica se as dependências estão disponíveis
    if not check_dependencies():
        print("Dependências ausentes. Abortando execução.")
        return 1
    
    # Configura o sistema de logging
    setup_logging(os.path.join(BASE_CONFIG["logs_dir"], "execucoes.log"))

    # Prepara o ambiente com base no tipo de aplicação
    app_module = setup_environment(args.app)
    if not app_module:
        return 1
    
    # Configura monitor de status de variantes
    status_monitor = VariantStatusMonitor()
    
    # Encontra as variantes a serem simuladas baseado no tipo de aplicação
    variants_to_simulate, _ = app_module.find_variants_to_simulate(BASE_CONFIG)
    
    # Verifica se existe checkpoint para continuar execução anterior
    processed_variants_set, processed_count, total_count = load_checkpoint(BASE_CONFIG)
    if processed_variants_set and total_count > 0:
        resume = input(f"Encontrado checkpoint com {processed_count}/{total_count} variantes processadas. Continuar? (s/n): ")
        if resume.lower() in ('s', 'sim', 'y', 'yes'):
            # Filtra as variantes já processadas
            variants_to_simulate = [(f, h) for f, h in variants_to_simulate if h not in processed_variants_set]
            print(f"Continuando execução com {len(variants_to_simulate)} variantes pendentes...")
        else:
            # Reinicia do zero
            processed_variants_set = set()
    else:
        processed_variants_set = set()
    
    # Inicia o monitor de status
    status_monitor.start()
    
    # Antes do ThreadPoolExecutor
    start_time = datetime.now()
    
    # Processa as variantes em paralelo
    if variants_to_simulate:
        print(f"Processando {len(variants_to_simulate)} variantes...")
        
        successful_variants = 0
        failed_variants = 0
        
        # E ajuste o código:
        if args.workers > 0:
            max_workers = args.workers
        else:
            max_workers = max(1, os.cpu_count() - 1)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for file, variant_hash in variants_to_simulate:
                futures[executor.submit(
                    app_module.simulate_variant, 
                    file, 
                    variant_hash, 
                    BASE_CONFIG, 
                    status_monitor
                )] = (file, variant_hash)
            
            # Processa os resultados à medida que são concluídos
            for future in as_completed(futures):
                file, variant_hash = futures[future]
                try:
                    result = future.result()
                    if result:
                        successful_variants += 1
                        print(f"Simulação da variante {short_hash(variant_hash)} concluída com sucesso")
                        # Marca a variante como executada com sucesso
                        add_executed_variant(variant_hash, BASE_CONFIG["executed_variants_file"])
                    else:
                        failed_variants += 1
                        print(f"Falha na simulação da variante {short_hash(variant_hash)}")
                        # Registra a variante que falhou
                        add_failed_variant(variant_hash, "execution_failure", BASE_CONFIG["failed_variants_file"])
                except Exception as e:
                    failed_variants += 1
                    print(f"Erro ao processar a variante {short_hash(variant_hash)}: {e}")
                    # Registra a falha com o erro específico
                    add_failed_variant(variant_hash, f"exception:{str(e)}", BASE_CONFIG["failed_variants_file"])
                
                processed_variants_set.add(variant_hash)
                if len(processed_variants_set) % 5 == 0:  # Salva a cada 5 variantes
                    save_checkpoint(len(processed_variants_set), len(variants_to_simulate), 
                                   processed_variants_set, BASE_CONFIG)
        
        # Após processar todas as variantes
        end_time = datetime.now()
        execution_duration = (end_time - start_time).total_seconds()

        # Gera relatório detalhado
        report_data = {
            "execution_start": start_time.isoformat(),
            "execution_end": end_time.isoformat(),
            "total_duration_seconds": execution_duration,
            "successful_variants": successful_variants,
            "failed_variants": failed_variants,
            "workers_used": max_workers
        }
        generate_report(report_data, BASE_CONFIG)
        
        print(f"Processamento concluído: {successful_variants} com sucesso, {failed_variants} falhas")
        return 0 if failed_variants == 0 else 1
    else:
        print("Nenhuma variante nova para simular")
    
    # Para o monitor de status
    status_monitor.stop()
    
    print("Processamento concluído!")
    return 0

if __name__ == '__main__':
    sys.exit(main())