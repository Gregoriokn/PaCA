import os
import glob
import logging
import subprocess

from code_parser import parse_code
from hash_utils import gerar_hash_codigo_logico
from database.variant_tracker import load_executed_variants
from utils.file_utils import short_hash, copy_file, TempFiles
from execution.compilation import generate_dump
from execution.simulation import run_spike_simulation, run_prof5, save_modified_lines

# Configurações específicas para a aplicação JMEINT
JMEINT_CONFIG = {
    # Arquivos específicos da aplicação
    "jmeint_main_file": "axbench/applications/jmeint/src/jmeint.cpp", # Renomeado para clareza
    "tritri_source_file": "axbench/applications/jmeint/src/tritri.cpp", # Arquivo original que pode ter variantes
    "train_data_input": "axbench/applications/jmeint/train.data/input/jmeint_10K.data",

    # Padrões de arquivos para variantes de tritri.cpp
    "source_pattern": "tritri_*.cpp", # Padrão para encontrar variantes de tritri.cpp
    "exe_prefix": "jmeint_",
    "output_suffix": ".data",
    "time_suffix": ".time",
    "prof5_suffix": ".prof5",

    # Parâmetros de geração de variantes (para tritri.cpp)
    "input_file_for_variants": "axbench/applications/jmeint/src/tritri.cpp",
    "operations_map": {'*': 'FMULX', '+': 'FADDX', '-': 'FSUBX'},

    # Parâmetros específicos de compilação
    "include_dir": "axbench/applications/jmeint/src",
    "optimization_level": "-O",
}

def prepare_environment(base_config):
    """Prepara o ambiente específico para a aplicação JMEINT"""
    config = {**base_config, **JMEINT_CONFIG}
    approx_source = config.get("approx_file", "data/reference/approx.h")
    return copy_file(approx_source, config["input_dir"])

def generate_variants(base_config):
    """Gera variantes específicas para tritri.cpp dentro do contexto de JMEINT"""
    from gera_variantes import main as gera_main
    
    config = {**base_config, **JMEINT_CONFIG}
    print(f"Gerando variantes para JMEINT (baseado em {config['input_file_for_variants']})")
    
    config_override = {
        "input_file": config["input_file_for_variants"],
        "operations_map": config["operations_map"],
        "executed_variants_file": config["executed_variants_file"]
    }
    return gera_main(config_override)

def find_variants_to_simulate(base_config):
    """Identifica as combinações de JMEINT (com variantes de tritri.cpp) que precisam ser simuladas."""
    config = {**base_config, **JMEINT_CONFIG}
    executed_variants = load_executed_variants(config["executed_variants_file"])
    variants_to_simulate = []

    # Mapa lógico do arquivo tritri.cpp original (base para hashes das variantes)
    tritri_original_path = config["tritri_source_file"]
    with open(tritri_original_path, "r") as f:
        tritri_original_lines = f.readlines()
    _, __, tritri_original_physical_to_logical = parse_code(tritri_original_path)
    
    # Hash da versão original de tritri.cpp
    tritri_original_hash = gerar_hash_codigo_logico(tritri_original_lines, tritri_original_physical_to_logical)

    # Adicionar a simulação da versão totalmente original (jmeint.cpp original + tritri.cpp original)
    # O hash identificador será o do tritri.cpp original
    if tritri_original_hash not in executed_variants:
        variants_to_simulate.append((tritri_original_path, tritri_original_hash))
        logging.info(f"Versão original de JMEINT (jmeint.cpp + {os.path.basename(tritri_original_path)}) será simulada (hash: {short_hash(tritri_original_hash)})")
    else:
        logging.info(f"Versão original de JMEINT (jmeint.cpp + {os.path.basename(tritri_original_path)}) já foi executada (hash: {short_hash(tritri_original_hash)})")

    # Buscar por variantes de tritri.cpp
    variant_pattern = os.path.join(config["input_dir"], config["source_pattern"])
    logging.info(f"Buscando variantes de tritri.cpp em: {variant_pattern}")
    for variant_tritri_file_path in glob.glob(variant_pattern):
        if os.path.abspath(variant_tritri_file_path) == os.path.abspath(tritri_original_path):
            continue # Já tratado como "original"

        with open(variant_tritri_file_path, "r") as f:
            variant_lines = f.readlines()
        # Usar o mapa do tritri.cpp original para calcular o hash da variante
        variant_tritri_hash = gerar_hash_codigo_logico(variant_lines, tritri_original_physical_to_logical)
        
        if variant_tritri_hash not in executed_variants:
            variants_to_simulate.append((variant_tritri_file_path, variant_tritri_hash))
            logging.info(f"Variante JMEINT (jmeint.cpp + {os.path.basename(variant_tritri_file_path)}) será simulada (hash: {short_hash(variant_tritri_hash)})")
        else:
            logging.info(f"Variante JMEINT (jmeint.cpp + {os.path.basename(variant_tritri_file_path)}) já foi executada (hash: {short_hash(variant_tritri_hash)})")
            
    return variants_to_simulate, tritri_original_physical_to_logical # Retorna o mapa do tritri original

def compile_jmeint_variant(jmeint_cpp_to_compile, tritri_cpp_to_compile, output_naming_hash, config, status_monitor):
    """Compilação especializada: jmeint.cpp (fixo) + tritri.cpp (variável)."""
    
    # Determina o ID da variante com base no arquivo tritri.cpp
    is_tritri_original = (os.path.abspath(tritri_cpp_to_compile) == os.path.abspath(config["tritri_source_file"]))
    variant_id = "original" if is_tritri_original else short_hash(output_naming_hash)
    status_monitor.update_status(variant_id, "Compilando JMEINT")

    exe_prefix = config.get("exe_prefix", "jmeint_")
    executables_dir = config["executables_dir"]
    optimization = config.get("optimization_level", "-O")

    # Nomes dos arquivos objeto e executável são baseados no hash do tritri.cpp (output_naming_hash)
    jmeint_obj_file = os.path.join(executables_dir, f"{exe_prefix}{output_naming_hash}_jmeint.o")
    tritri_obj_file = os.path.join(executables_dir, f"{exe_prefix}{output_naming_hash}_tritri.o")
    exe_file = os.path.join(executables_dir, f"{exe_prefix}{output_naming_hash}")

    include_flags = ["-I", config["include_dir"], "-I", config["input_dir"]]

    # Compilar jmeint.cpp (sempre o mesmo arquivo fonte)
    compile_jmeint_cmd = [
        "riscv32-unknown-elf-g++", "-march=rv32imafdc", optimization, *include_flags,
        "-c", jmeint_cpp_to_compile, "-o", jmeint_obj_file, "-lm"
    ]
    try:
        result = subprocess.run(compile_jmeint_cmd, check=True, capture_output=True, text=True)
        if result.stderr: logging.warning(f"[Variante {variant_id} - jmeint.cpp] Avisos: {result.stderr.strip()}")
        logging.info(f"[Variante {variant_id}] Compilado {os.path.basename(jmeint_cpp_to_compile)} -> {os.path.basename(jmeint_obj_file)}")
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variante {variant_id} - jmeint.cpp] Erro compilação: {e.stderr.strip()}")
        status_monitor.update_status(variant_id, "Erro Compilação (jmeint.cpp)")
        return False, None

    # Compilar tritri.cpp (pode ser o original ou uma variante)
    compile_tritri_cmd = [
        "riscv32-unknown-elf-g++", "-march=rv32imafdc", optimization, *include_flags,
        "-c", tritri_cpp_to_compile, "-o", tritri_obj_file, "-lm"
    ]
    try:
        result = subprocess.run(compile_tritri_cmd, check=True, capture_output=True, text=True)
        if result.stderr: logging.warning(f"[Variante {variant_id} - {os.path.basename(tritri_cpp_to_compile)}] Avisos: {result.stderr.strip()}")
        logging.info(f"[Variante {variant_id}] Compilado {os.path.basename(tritri_cpp_to_compile)} -> {os.path.basename(tritri_obj_file)}")
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variante {variant_id} - {os.path.basename(tritri_cpp_to_compile)}] Erro compilação: {e.stderr.strip()}")
        status_monitor.update_status(variant_id, f"Erro Compilação ({os.path.basename(tritri_cpp_to_compile)})")
        return False, None

    # Linkar os dois arquivos objeto
    link_cmd = [
        "riscv32-unknown-elf-g++", "-march=rv32imafdc",
        jmeint_obj_file, tritri_obj_file, "-o", exe_file, "-lm"
    ]
    try:
        result = subprocess.run(link_cmd, check=True, capture_output=True, text=True)
        if result.stderr: logging.warning(f"[Variante {variant_id}] Avisos (link): {result.stderr.strip()}")
        logging.info(f"[Variante {variant_id}] Linkado -> {os.path.basename(exe_file)}")
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variante {variant_id}] Erro linkagem: {e.stderr.strip()}")
        status_monitor.update_status(variant_id, "Erro Linkagem JMEINT")
        return False, None

    os.chmod(exe_file, 0o755)
    status_monitor.update_status(variant_id, "Compilado JMEINT")
    return True, exe_file

def simulate_variant(current_tritri_filepath, current_tritri_hash, base_config, status_monitor):
    """
    Simula uma combinação de JMEINT.
    current_tritri_filepath: Caminho para o arquivo tritri.cpp (original ou variante) a ser usado.
    current_tritri_hash: Hash lógico do current_tritri_filepath, usado para nomear saídas e rastreamento.
    """
    config = {**base_config, **JMEINT_CONFIG}
    
    # Determina o ID da variante com base no arquivo tritri.cpp
    is_tritri_original = (os.path.abspath(current_tritri_filepath) == os.path.abspath(config["tritri_source_file"]))
    variant_id = "original" if is_tritri_original else short_hash(current_tritri_hash)

    exe_prefix = config["exe_prefix"]
    outputs_dir = config["outputs_dir"]
    logs_dir = config["logs_dir"]
    dump_dir = config["dump_dir"]
    prof5_results_dir = config["prof5_results_dir"]

    # Nomes de arquivo de saída são baseados no hash do tritri.cpp (current_tritri_hash)
    spike_output_file = os.path.join(outputs_dir, f"{exe_prefix}{current_tritri_hash}{config['output_suffix']}")
    time_file = os.path.join(outputs_dir, f"{exe_prefix}{current_tritri_hash}{config['time_suffix']}")
    prof5_time_file = os.path.join(outputs_dir, f"{exe_prefix}{current_tritri_hash}{config['prof5_suffix']}")
    spike_log_file = os.path.join(logs_dir, f"{exe_prefix}{current_tritri_hash}.log")
    dump_file = os.path.join(dump_dir, f"dump_{current_tritri_hash}.txt")
    prof5_report_path = os.path.join(prof5_results_dir, f"prof5_results_{current_tritri_hash}.json")

    # Arquivos a serem compilados
    jmeint_to_compile = config["jmeint_main_file"]
    tritri_to_compile = current_tritri_filepath 
    
    # O hash usado para nomear arquivos de compilação e executável é o hash do tritri.cpp
    output_naming_hash = current_tritri_hash

    with TempFiles([spike_log_file, dump_file]): # dump_file é temporário? Geralmente não.
                                                # Se não for, remova-o de TempFiles.
        compiled_ok, exe_file = compile_jmeint_variant(
            jmeint_to_compile, 
            tritri_to_compile, 
            output_naming_hash, 
            config, 
            status_monitor
        )
        if not compiled_ok: return False

        if not generate_dump(exe_file, dump_file, variant_id, status_monitor): return False

        sim_time = run_spike_simulation(
            exe_file, config["train_data_input"], spike_output_file,
            spike_log_file, variant_id, status_monitor
        )
        if sim_time is None: return False
        with open(time_file, 'w') as tf: tf.write(f"{sim_time}\n")
        os.chmod(time_file, 0o666)

        prof5_time = run_prof5(
            exe_file, spike_log_file, dump_file, config["prof5_model"],
            config["prof5_executable"], prof5_time_file, prof5_report_path,
            variant_id, status_monitor
        )
        if prof5_time is None: return False
        
        # Salva as linhas modificadas do arquivo tritri.cpp em relação ao seu original
        save_modified_lines(current_tritri_filepath, config["tritri_source_file"], 
                              current_tritri_hash, config, parse_code)

    logging.info(f"[Variante {variant_id}] Simulação JMEINT completa com sucesso!")
    status_monitor.update_status(variant_id, "Concluída JMEINT")
    return True