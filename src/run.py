#!/usr/bin/env python3
# filepath: /Users/gregoriokoslinskineto/Documents/Mestrado/BancoDeDados/run.py

import os
import sys
import glob
import re
import time
import shutil
import subprocess
import json
import pandas as pd
import numpy as np
import hashlib
import logging
import threading
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from gera_variantes import parse_code, gerar_hash_codigo_logico  # Importa as funções necessárias

# Atualizar configurações globais no arquivo run.py
CONFIG = {
    "executables_dir": "codigos_executaveis",
    "outputs_dir": "outputs",
    "logs_dir": "Logs",  
    "input_dir": "codigos_modificados",
    "approx_file": "approx.h",
    "train_data_input": "inversek2j/train.data/input/1k.data",
    "prof5_model": "../prof5/models/APPROX_1.json",
    "prof5_executable": "../prof5/prof5",
    "parquet_file": "execucoes.parquet",
    "original_file": "inversek2j/src/kinematics.cpp",
    "inversek2j_object": "inversek2j.o",  # Objeto inversek2j.o fixo
    "max_log_bytes": 200 * 1024 * 1024 * 1024  # 50GB
}



# Dicionário global para armazenar o status de cada variante
STATUS_DICT = {}
STATUS_LOCK = threading.Lock()
LAST_STATUS = {}  # Para armazenar o último estado conhecido de cada variante
simulated_variants_counter = 0
simulated_variants_counter_lock = threading.Lock()

def update_status(variant, message):
    """Atualiza o status de uma variante e retorna True se houve mudança"""
    with STATUS_LOCK:
        if variant not in STATUS_DICT or STATUS_DICT[variant] != message:
            STATUS_DICT[variant] = message
            return True
        return False

# Função de monitoramento de status
def monitor_statuses(stop_event):
    while not stop_event.is_set():
        with STATUS_LOCK:
            # Verifica se houve alguma mudança desde o último status
            changes = []
            for variant, status in STATUS_DICT.items():
                if variant not in LAST_STATUS or LAST_STATUS[variant] != status:
                    changes.append((variant, status))
                    LAST_STATUS[variant] = status
            
            # Só imprime se houver mudanças
            if changes:
                logging.info("------ Atualizações de Status ------")
                for variant, status in sorted(changes):  # Ordena por variante
                    logging.info(f"Variante {variant}: {status}")
                logging.info("------ Fim das atualizações ------\n")
        
        time.sleep(0.5)  # Reduz o intervalo de verificação para ser mais responsivo

# --------------------------------------------------
# CONFIGURAÇÃO E PREPARAÇÃO DO AMBIENTE
# --------------------------------------------------
def check_data_in_db(hash_value, df_db, field=None):
    """
    Verifica se os dados de uma variante já estão completos no banco.
    Se field for especificado, verifica apenas aquele campo.
    """
    if df_db is None or df_db.empty:
        return False
        
    mask = df_db['codigo_modificado_hash'] == hash_value
    if not mask.any():
        return False
        
    entry = df_db[mask].iloc[0]
    
    if field:
        # Verifica apenas o campo específico
        if field == 'output':
            return not (entry['output'] is None or
                       pd.isna(entry['output']) or
                       entry['output'].strip() in ["", "Arquivo não gerado"])
        elif field == 'Tempo prof5':
            return not (entry['Tempo prof5'] is None or
                       pd.isna(entry['Tempo prof5']) or
                       str(entry['Tempo prof5']).strip() == "")
        elif field == 'Prof5_outputs':
            return not (entry['Prof5_outputs'] is None or
                       pd.isna(entry['Prof5_outputs']) or
                       not entry['Prof5_outputs'])
        return True
    
    # Verifica todos os campos
    return not (entry['output'] is None or
               pd.isna(entry['output']) or
               entry['output'].strip() in ["", "Arquivo não gerado"] or
               entry['Tempo prof5'] is None or
               pd.isna(entry['Tempo prof5']) or
               str(entry['Tempo prof5']).strip() == "" or
               entry['Prof5_outputs'] is None or
               pd.isna(entry['Prof5_outputs']) or
               not entry['Prof5_outputs'])

def clean_output_files(config):
    """Limpa arquivos de output, preservando aqueles que ainda não foram salvos no banco"""
    
    # Carrega o banco de dados atual
    df_db = None
    if os.path.exists(config["parquet_file"]):
        df_db = pd.read_parquet(config["parquet_file"])
    
    # Lista de extensões para limpar
    extensions = ['.data', '.time', '.log', '.prof5']
    
    # Função auxiliar para extrair hash do nome do arquivo
    def extract_hash(filename):
        parts = filename.split('_')
        if len(parts) > 1:
            return parts[1].split('.')[0]
        return None
    
    # Limpa a pasta outputs
    for ext in extensions:
        files = glob.glob(os.path.join(config["outputs_dir"], f"*{ext}"))
        for f in files:
            try:
                hash_value = extract_hash(os.path.basename(f))
                if hash_value and check_data_in_db(hash_value, df_db):
                    # Se os dados já estão no banco, pode apagar
                    os.chmod(f, 0o666)
                    os.remove(f)
                    logging.info(f"Arquivo removido (dados já no banco): {f}")
                else:
                    logging.info(f"Arquivo preservado (dados não encontrados no banco): {f}")
            except Exception as e:
                logging.warning(f"Não foi possível processar {f}: {e}")
    
    # Limpa a pasta prof5Results
    prof5_files = glob.glob(os.path.join("prof5Results", "*.json"))
    for f in prof5_files:
        try:
            hash_value = extract_hash(os.path.basename(f))
            if hash_value and check_data_in_db(hash_value, df_db):
                os.chmod(f, 0o666)
                os.remove(f)
                logging.info(f"Arquivo removido (dados já no banco): {f}")
            else:
                logging.info(f"Arquivo preservado (dados não encontrados no banco): {f}")
        except Exception as e:
            logging.warning(f"Não foi possível processar {f}: {e}")
    
    # Limpa a pasta dump
    dump_files = glob.glob(os.path.join("dump", "*.txt"))
    for f in dump_files:
        try:
            hash_value = extract_hash(os.path.basename(f))
            if hash_value and check_data_in_db(hash_value, df_db):
                os.chmod(f, 0o666)
                os.remove(f)
                logging.info(f"Arquivo removido (dados já no banco): {f}")
            else:
                logging.info(f"Arquivo preservado (dados não encontrados no banco): {f}")
        except Exception as e:
            logging.warning(f"Não foi possível processar {f}: {e}")
            
    # Limpa os executáveis
    exe_files = glob.glob(os.path.join(config["executables_dir"], "kinematics_*"))
    for f in exe_files:
        try:
            hash_value = extract_hash(os.path.basename(f))
            if hash_value and check_data_in_db(hash_value, df_db):
                os.chmod(f, 0o777)  # Dá todas as permissões para executáveis
                os.remove(f)
                logging.info(f"Executável removido (dados já no banco): {f}")
            else:
                logging.info(f"Executável preservado (dados não encontrados no banco): {f}")
        except Exception as e:
            logging.warning(f"Não foi possível remover o executável {f}: {e}")


def setup_environment():
    global CONFIG
    os.environ["PATH"] += ":/opt/riscv/bin"
    dirs = [CONFIG["executables_dir"], CONFIG["outputs_dir"], CONFIG["input_dir"], 
            "prof5Results", "dump", CONFIG["logs_dir"]]  # Adicionada pasta de logs
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    
    # Limpa os arquivos de output antes de começar
    clean_output_files(CONFIG)
    
    logging.info("Gerando variantes...")
    subprocess.run(["python3", "gera_variantes.py"], check=True)
    approx_file = CONFIG["approx_file"]
    input_dir = CONFIG["input_dir"]
    if os.path.exists(approx_file):
        shutil.copy(approx_file, input_dir)
        logging.info(f"Arquivo {approx_file} copiado para {input_dir}")
    else:
        logging.error(f"Arquivo {approx_file} não encontrado!")
        sys.exit(1)
# --------------------------------------------------
# FUNÇÕES AUXILIARES
# --------------------------------------------------
def get_log_folder_size(logs_dir):
    total = 0
    for root, dirs, files in os.walk(logs_dir):
        for f in files:
            if f.endswith(".log"):
                total += os.path.getsize(os.path.join(root, f))
    return total

LOG_SPACE_LOCK = threading.Lock()

def short_hash(hash_value):
    return hash_value[:8] if isinstance(hash_value, str) else ""

# Função corrigida com indentação adequada
def wait_for_available_log_space(logs_dir, max_bytes):
    with LOG_SPACE_LOCK:  # Apenas uma thread verifica por vez
        current_size = get_log_folder_size(logs_dir)
        if current_size > max_bytes:
            logging.info(f"Thread {threading.current_thread().name}: Pasta de logs excedeu o limite ({current_size/1024/1024:.2f}MB)")
            time.sleep(2)  # Tempo reduzido
            return False  # Indica que precisa verificar novamente
    return True  # Pode continuar
        
def extrair_numero(file_path):
    match = re.findall(r'\d+', os.path.basename(file_path))
    return match[0] if match else ""

def get_modified_lines_physical(orig_lines, mod_lines):
    modified_indices = []
    size = min(len(orig_lines), len(mod_lines))
    for i in range(size):
        if orig_lines[i] != mod_lines[i]:
            modified_indices.append(i)
    if len(mod_lines) > size:
        modified_indices.extend(range(size, len(mod_lines)))
    return modified_indices

def salvar_linhas_hash(variant_file, config, original_file, codigo_hash=None):
    """
    Compara o código original com o da variante e salva as linhas modificadas
    em um arquivo na pasta de outputs, com o nome linhas_hash_<hash>.txt.
    
    Se codigo_hash for fornecido, usa esse valor em vez de recalcular.
    """
    import os
    # Lê o arquivo original e o da variante
    with open(original_file, "r") as f:
        original_lines = f.readlines()
    with open(variant_file, "r") as f:
        variant_lines = f.readlines()
    # Obtém o mapeamento físico -> lógico do código original
    _, __, original_physical_to_logical = parse_code(original_file)
    # Calcula as linhas modificadas (lógicas)
    modified_logical = get_modified_logical_lines(original_lines, variant_lines, original_physical_to_logical)
    # Usa o hash fornecido ou calcula-o
    if not codigo_hash:
        codigo_hash = gerar_hash_codigo_logico(variant_lines, original_physical_to_logical)
    # Define o caminho do arquivo de saída na pasta outputs
    output_file = os.path.join(config["outputs_dir"], f"linhas_hash_{codigo_hash}.txt")
    # Remove arquivo existente (evita duplicadas)
    if os.path.exists(output_file):
        os.remove(output_file)
    # Salva cada linha modificada no arquivo
    with open(output_file, "w") as f:
        for line in modified_logical:
            f.write(str(line) + "\n")
    logging.info(f"Arquivo '{output_file}' gerado com sucesso para a variante {short_hash(codigo_hash)}.")

# --------------------------------------------------
# FUNÇÃO DE SIMULAÇÃO PARA UMA VARIANTE
# --------------------------------------------------
def load_executed_variants(file_path="executados.txt"):
    """Carrega os hashes das variantes já executadas"""
    executed = set()
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()  # Remove espaços extras e quebras de linha
                if line:  # Ignora linhas vazias
                    executed.add(line)
        
        # Mostra debug detalhado
        print(f"DEBUG: Arquivo {file_path} existe. Carregados {len(executed)} hashes.")
        if executed:
            examples = list(executed)[:3]
            print(f"DEBUG: Exemplos de hashes: {examples}")
            
            # Verificar se a versão original está incluída
            with open(CONFIG["original_file"], "r") as f:
                original_lines = f.readlines()
            _, __, original_physical_to_logical = parse_code(CONFIG["original_file"])
            original_hash = gerar_hash_codigo_logico(original_lines, original_physical_to_logical)
            
            if original_hash in executed:
                print(f"DEBUG: Hash da versão original ESTÁ no executed_variants!")
                print(f"DEBUG: Hash original: {original_hash}")
            else:
                print(f"DEBUG: Hash da versão original NÃO está no executed_variants!")
                print(f"DEBUG: Hash original: {original_hash}")
                
                # Verifica se algum hash similar está presente 
                for h in executed:
                    if original_hash.startswith(h) or h.startswith(original_hash):
                        print(f"DEBUG: Encontrada correspondência parcial: {h}")
    else:
        print(f"DEBUG: Arquivo {file_path} não existe!")
    return executed
def add_executed_variant(codigo_hash, file_path="executados.txt"):
    """Adiciona o hash de uma variante executada no arquivo"""
    with open(file_path, "a") as f:
        f.write(codigo_hash + "\n")

def check_output_files(file, config):
    """Verifica se todos os arquivos de output necessários existem e não estão vazios"""
    # Extrai o hash do nome do arquivo
    hash_prefix = os.path.basename(file).split('_')[-1].split('.')[0]
    
    # Define os novos nomes de arquivos para inversek2j
    output_path = os.path.join(config["outputs_dir"], f"kinematics_{hash_prefix}.data")
    time_path = os.path.join(config["outputs_dir"], f"kinematics_{hash_prefix}.time")
    prof5_time_path = os.path.join(config["outputs_dir"], f"kinematics_{hash_prefix}.prof5")
    prof5_report_path = os.path.join("prof5Results", f"prof5_results_{hash_prefix}.json")
    
    # Lista de arquivos para verificar
    files_to_check = [
        (output_path, "arquivo de output"),
        (time_path, "arquivo de tempo"),
        (prof5_time_path, "arquivo de tempo do Prof5"),
        (prof5_report_path, "arquivo de resultados do Prof5")
    ]
    
    # Verifica cada arquivo (resto da função permanece igual)
    # ...
    
    # Verifica cada arquivo
    for file_path, desc in files_to_check:
        # Verifica se o arquivo existe
        if not os.path.exists(file_path):
            return False, f"{desc} não existe"
        
        # Verifica se o arquivo está vazio
        if os.path.getsize(file_path) == 0:
            return False, f"{desc} está vazio"
        
        # Verifica o conteúdo dos arquivos
        try:
            with open(file_path, 'r') as f:
                content = f.read().strip()
                if not content:
                    return False, f"{desc} está vazio (conteúdo em branco)"
                
                # Verificações específicas por tipo de arquivo
                if file_path.endswith('.data'):
                    try:
                        numbers = [float(x) for x in content.split()]
                        if not numbers:
                            return False, f"{desc} não contém números válidos"
                    except ValueError:
                        return False, f"{desc} contém dados inválidos"
                elif file_path.endswith('.json'):
                    try:
                        import json
                        data = json.loads(content)
                        if not data:
                            return False, f"{desc} contém JSON vazio"
                    except json.JSONDecodeError:
                        return False, f"{desc} contém JSON inválido"
        except Exception as e:
            return False, f"Erro ao ler {desc}: {str(e)}"
    
    return True, None

def check_simulation_needed(file, config):
    """Verifica se uma simulação é necessária verificando se já temos dados válidos"""
    # Gera o hash do código fonte
    with open(file, "r") as f:
        lines = f.readlines()
    _, __, physical_to_logical = parse_code(file)
    codigo_hash = gerar_hash_codigo_logico(lines, physical_to_logical)
    
    # Verifica se já existe no banco e se os dados estão completos
    if os.path.exists(config["parquet_file"]):
        df = pd.read_parquet(config["parquet_file"])
        if check_data_in_db(codigo_hash, df):
            return False, codigo_hash
    
    # Verifica se os arquivos estão na pasta de processados
    processed_dir = os.path.join(os.getcwd(), "processados")
    prof5_processed = os.path.join(processed_dir, "prof5Results")
    prof5_file = os.path.join(prof5_processed, f"prof5_results_{codigo_hash}.json")
    
    if os.path.exists(prof5_file):
        logging.info(f"Arquivos da variante {codigo_hash[:8]} encontrados na pasta de processados")
        return False, codigo_hash
    
    # Verifica se todos os arquivos de output existem e são válidos
    files_ok, _ = check_output_files(file, config)
    return not files_ok, codigo_hash

def compilar_e_simular(file, config, sem_banco=False):
    # Primeiro verifica se precisamos simular (a menos que sem_banco=True)
    if not sem_banco:
        needs_simulation, codigo_hash = check_simulation_needed(file, config)
        if not needs_simulation:
            return None, None, None, None
    else:
        # Se --semBanco, gera o hash sem verificar se já existe
        with open(file, "r") as f:
            lines = f.readlines()
        _, __, physical_to_logical = parse_code(file)
        codigo_hash = gerar_hash_codigo_logico(lines, physical_to_logical)

    # Verifica se o arquivo de input existe
    if not os.path.exists(config["train_data_input"]):
        logging.error(f"Arquivo de input não encontrado: {config['train_data_input']}")
        return None, None, None, None

    # Dentro de compilar_e_simular, após gerar o codigo_hash:
    executed_variants = load_executed_variants("executados.txt")
    if codigo_hash in executed_variants:
        logging.info(f"Variante {codigo_hash[:8]} já executada. Saltando simulação.")
        return None, None, None, None
        
    # Se for o arquivo original, usa "original" como identificador nos logs
    is_original = (file == config["original_file"])
    variant_id = "original" if is_original else codigo_hash[:8]
    
    update_status(variant_id, "Iniciando")
    
    # Definir nomes de arquivos
    obj_file = os.path.join(config["executables_dir"], f"kinematics_{codigo_hash}.o")
    exe = os.path.join(config["executables_dir"], f"kinematics_{codigo_hash}")
    output = os.path.join(config["outputs_dir"], f"kinematics_{codigo_hash}.data")
    time_file = os.path.join(config["outputs_dir"], f"kinematics_{codigo_hash}.time")
    spike_log_file = os.path.join(config["logs_dir"], f"kinematics_{codigo_hash}.log")
    prof5_time_file = os.path.join(config["outputs_dir"], f"kinematics_{codigo_hash}.prof5")
    prof5_report_path = os.path.join("prof5Results", f"prof5_results_{codigo_hash}.json")
    dump_file = os.path.join("dump", f"dump_{codigo_hash}.txt")
    
    # PASSO 1: Compilar kinematics.cpp para kinematics.o
    update_status(variant_id, "Compilando kinematics.o")
    compile_cmd = [
        "riscv32-unknown-elf-g++",
        "-march=rv32imafdc",
        "-I", "inversek2j/src", 
        "-I", config["input_dir"],
        "-c", file,
        "-o", obj_file,
        "-lm"
    ]
    try:
        result = subprocess.run(compile_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stderr:
            logging.info(f"[Variante {variant_id[:8]}] Avisos de compilação: {result.stderr.decode()}")
        if is_original:
            logging.info("[Versão original] Compilação do objeto concluída.")
        else:
            logging.info(f"[Variante {variant_id[:8]}] Compilação do objeto concluída.")
    except subprocess.CalledProcessError as e:
        if is_original:
            logging.error(f"[Versão original] Erro na compilação do objeto: {e.stderr.decode()}")
            update_status(variant_id, "Erro na compilação do objeto")
        else:
            logging.error(f"[Variante {variant_id[:8]}] Erro na compilação do objeto: {e.stderr.decode()}")
            update_status(variant_id[:8], "Erro na compilação do objeto")
        return None, None, None, None
    
    # PASSO 2: Linkar kinematics.o com inversek2j.o para gerar o executável
    update_status(variant_id, "Linkando executável")
    link_cmd = [
        "riscv32-unknown-elf-g++",
        "-march=rv32imafdc",
        config["inversek2j_object"],
        obj_file,
        "-o", exe,
        "-lm"
    ]
    try:
        result = subprocess.run(link_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stderr:
            logging.info(f"[Variante {variant_id[:8]}] Avisos de linkagem: {result.stderr.decode()}")
        if is_original:
            logging.info("[Versão original] Linkagem concluída.")
        else:
            logging.info(f"[Variante {variant_id[:8]}] Linkagem concluída.")
    except subprocess.CalledProcessError as e:
        if is_original:
            logging.error(f"[Versão original] Erro na linkagem: {e.stderr.decode()}")
            update_status(variant_id, "Erro na linkagem")
        else:
            logging.error(f"[Variante {variant_id[:8]}] Erro na linkagem: {e.stderr.decode()}")
            update_status(variant_id[:8], "Erro na linkagem")
        return None, None, None, None

       # Cria o output vazio (necessário para o spike)
    open(output, 'w').close()
    os.chmod(output, 0o666)  # Define permissões de leitura e escrita para todos
    
    # Verifica espaço disponível para logs
    # while not wait_for_available_log_space(config["logs_dir"], config["max_log_bytes"]):
    #     pass  # Continua verificando até ter espaço
    
    # Simulação com Spike
    update_status(variant_id, "Simulando com Spike")
    if is_original:
        logging.info("[Versão original] Iniciando simulação com Spike...")
    else:
        logging.info(f"[Variante {variant_id[:8]}] Iniciando simulação com Spike...")
    
    # Verifica se o executável existe e tem permissão de execução
    if not os.path.exists(exe):
        logging.error(f"[Variante {variant_id[:8]}] Executável não encontrado: {exe}")
        return None, None, None, None
    os.chmod(exe, 0o755)  # Garante permissão de execução
    
    # Comando spike atualizado para inversek2j
    sim_cmd = [
        "spike",
        "--isa=RV32IMAFDC",
        "-l",
        f"--log={spike_log_file}",
        "/opt/riscv/riscv32-unknown-elf/bin/pk",
        exe,
        config["train_data_input"],
        output
    ]
    
    # Executa o spike e mede o tempo
    start = time.perf_counter()
    try:
        result = subprocess.run(sim_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stderr:
            logging.info(f"[Variante {variant_id}] Saída de erro do Spike: {result.stderr.decode()}")
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variante {variant_id}] Erro na simulação: {e.stderr.decode()}")
        update_status(variant_id, "Erro na simulação")
        return None, None, None, None
    end = time.perf_counter()
    runtime = end - start
    
    # Salva o tempo de execução
    tempo_sim = runtime
    with open(time_file, 'w') as tf:
        tf.write(f"{runtime}\n")
    os.chmod(time_file, 0o666)
    logging.info(f"[Variante {variant_id}] Simulada em {runtime:.6f} segundos.")
    
    # Geração do dump
    update_status(variant_id, "Gerando Dump")
    dump_cmd = [
        "riscv32-unknown-elf-objdump",
        "-d",
        exe
    ]
    try:
        with open(dump_file, "w") as df:
            subprocess.run(dump_cmd, check=True, stdout=df, stderr=subprocess.PIPE)
        os.chmod(dump_file, 0o666)
        logging.info(f"[Variante {variant_id}] Dump gerado em {dump_file}")
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variante {variant_id}] Erro ao gerar dump: {e.stderr.decode()}")
        update_status(variant_id, "Erro no Dump")
        return None, None, None, None

    # Execução do Prof5
    update_status(variant_id, "Executando Prof5")
    if is_original:
        logging.info("[Versão original] Iniciando execução do Prof5...")
    else:
        logging.info(f"[Variante {variant_id[:8]}] Iniciando execução do Prof5...")
    
    prof5_cmd = [
        config["prof5_executable"],
        "-i", "RV32IMAFDC",
        "-l", spike_log_file,
        "-d", dump_file,
        "-m", config["prof5_model"],
        exe
    ]

    # Executa o prof5 e mede o tempo
    start_prof5 = time.perf_counter()
    try:
        subprocess.run(prof5_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info(f"[Variante {variant_id}] Prof5 executado com sucesso.")
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variante {variant_id}] Erro ao executar Prof5: {e.stderr.decode()}")
        update_status(variant_id, "Erro no Prof5")
        return None, None, None, None
    end_prof5 = time.perf_counter()
    tempo_prof5 = end_prof5 - start_prof5
    
    # Salva o tempo do prof5
    with open(prof5_time_file, "w") as pf:
        pf.write(f"{tempo_prof5}\n")
    os.chmod(prof5_time_file, 0o666)
    logging.info(f"[Variante {variant_id}] Prof5 executado em {tempo_prof5:.6f} segundos.")

        # Após mover o arquivo de resultados do Prof5:
    if os.path.exists(prof5_report_path):
        try:
            with open(prof5_report_path, "r") as f:
                data = json.load(f)
            if not data.get("all"):
                data["all"] = {"_dummy": None}
            prof5_outputs = {"all": data["all"]}
            logging.info(f"Prof5 outputs carregados de {prof5_report_path}")
        except Exception as e:
            logging.error(f"Erro ao ler o arquivo Prof5: {e}")
            prof5_outputs = {"all": {"_dummy": None}}
    else:
        logging.warning(f"Arquivo de resultados do Prof5 não encontrado: {prof5_report_path}")
        prof5_outputs = {"all": {"_dummy": None}}

    # Procura pelo arquivo JSON na pasta reports que corresponda ao hash da variante
    report_pattern = os.path.join("reports", f"kinematics_{codigo_hash}*", "*/prof5_results.json")
    match = glob.glob(report_pattern)
    if match:
        # Supondo que exista apenas um arquivo que combine com o padrão
        default_prof5_json = match[0]
        shutil.move(default_prof5_json, prof5_report_path)
        logging.info(f"Arquivo {default_prof5_json} movido para {prof5_report_path}")
    else:
        logging.warning(f"Arquivo de resultados do Prof5 não encontrado com o padrão {report_pattern}")

    # Após mover a saída do Prof5 (ou logo após carregar os dados)
    if os.path.exists(dump_file):
        os.chmod(dump_file, 0o666)
        os.remove(dump_file)
        logging.info(f"[Variante {variant_id}] Dump removido: {dump_file}")

    # Apaga o arquivo de log do Spike, se existir
    if os.path.exists(spike_log_file):
        os.chmod(spike_log_file, 0o666)
        os.remove(spike_log_file)
        logging.info(f"Arquivo de log removido: {spike_log_file[:8]}...")

    # Incrementa o contador de variantes simuladas
    global simulated_variants_counter
    with simulated_variants_counter_lock:
        simulated_variants_counter += 1
        logging.info(f"Simulação completa: {simulated_variants_counter} variantes executadas até agora.")

    # Após todas as etapas de simulação e profiling, chama a função para salvar as linhas modificadas
    # Note que 'file' é o caminho da variante e config["original_file"] é o código original.
    salvar_linhas_hash(file, config, config["original_file"], codigo_hash)
    add_executed_variant(codigo_hash)


    # Lê o conteúdo do arquivo de output
    output_content = None
    if os.path.exists(output):
        with open(output, 'r') as f:
            output_content = f.read().strip()

    # Define o diretório onde os arquivos executados serão movidos
    executados_dir = "Executados"
    os.makedirs(executados_dir, exist_ok=True)
    
    # Lista de pastas que você deseja mover, por exemplo: codigos_modificados, outputs, prof5Results, dump, Logs
    folders_to_move = [
        CONFIG["input_dir"],
        CONFIG["outputs_dir"],
        "prof5Results",
        CONFIG["logs_dir"]
    ]
    
    # Mova os arquivos correspondentes à variante processada (por exemplo, filtrando pelo hash)
    for folder in folders_to_move:
        pattern = os.path.join(folder, f"*{codigo_hash}*")
        for file in glob.glob(pattern):
            destination = os.path.join(executados_dir, os.path.basename(file))
            shutil.move(file, destination)
            logging.info(f"Arquivo {file} movido para {destination}")
    

    return output_content, tempo_sim, tempo_prof5, prof5_outputs

# --------------------------------------------------
# ATUALIZAÇÃO DO BANCO DE DADOS
# --------------------------------------------------
def get_modified_logical_lines(original_lines, modified_lines, original_physical_to_logical):
    """
    Retorna as linhas lógicas que foram marcadas para modificação.
    """
    # Primeiro, encontra as linhas que são marcadas com //anotacao:
    modifiable_lines = []
    for i, line in enumerate(original_lines):
        if re.match(r'^\s*//anotacao:\s*$', line):
            if i + 1 < len(original_lines):
                modifiable_lines.append(i + 1)

    # Depois, verifica quais dessas linhas foram realmente modificadas
    modified_logical_lines = []
    for physical_line in modifiable_lines:
        if physical_line < len(original_lines) and physical_line < len(modified_lines):
            orig = re.sub(r'\s+', ' ', original_lines[physical_line].strip())
            mod = re.sub(r'\s+', ' ', modified_lines[physical_line].strip())
            if orig != mod and physical_line in original_physical_to_logical:
                modified_logical_lines.append(original_physical_to_logical[physical_line])
    
    return sorted(modified_logical_lines)

def load_outputs(codigo_hash, config):
    """Carrega os outputs existentes dos arquivos"""
    output_content = None
    tempo_sim = None
    tempo_prof5 = None
    prof5_outputs = None
    
    output_file = os.path.join(config["outputs_dir"], f"kinematics_{codigo_hash}.data")
    time_file = os.path.join(config["outputs_dir"], f"kinematics_{codigo_hash}.time")
    prof5_time_file = os.path.join(config["outputs_dir"], f"kinematics_{codigo_hash}.prof5")
    prof5_report_path = os.path.join("prof5Results", f"prof5_results_{codigo_hash}.json")
    
    try:
        # Carrega o arquivo de output
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output_content = f.read().strip()
                if not output_content:
                    output_content = None
        
        # Carrega o arquivo de tempo de simulação
        if os.path.exists(time_file):
            with open(time_file, 'r') as f:
                content = f.read().strip()
                if content:
                    tempo_sim = float(content)
        
        # Carrega o arquivo de tempo do Prof5
        if os.path.exists(prof5_time_file):
            with open(prof5_time_file, 'r') as f:
                content = f.read().strip()
                if content:
                    tempo_prof5 = float(content)
        
        # Carrega o arquivo de resultados do Prof5
        if os.path.exists(prof5_report_path):
            try:
                with open(prof5_report_path, 'r') as f:
                    data = json.load(f)
                    # Cria um dicionário com a chave 'all' contendo os dados do Prof5
                    all_data = data.get('all', {})
                    # Se all_data estiver vazio, adiciona um campo dummy para evitar erro do Parquet
                    if not all_data:
                        all_data = {"_dummy": None}
                    prof5_outputs = {"all": all_data}
                    logging.info(f"Prof5 outputs carregados de {prof5_report_path}")
            except json.JSONDecodeError as e:
                logging.error(f"Erro ao decodificar JSON do Prof5 em {prof5_report_path}: {e}")
                prof5_outputs = {"all": {"_dummy": None}}
            except Exception as e:
                logging.error(f"Erro ao ler arquivo Prof5 {prof5_report_path}: {e}")
                prof5_outputs = {"all": {"_dummy": None}}
        else:
            logging.warning(f"Arquivo Prof5 não encontrado: {prof5_report_path}")
            prof5_outputs = {"all": {"_dummy": None}}
    
    except Exception as e:
        logging.error(f"Erro ao ler arquivos de output para hash {codigo_hash[:8]}: {str(e)}")
    
    return output_content, tempo_sim, tempo_prof5, prof5_outputs

def update_database(config, original_file, only_load_existing=False):
    """Atualiza o banco de dados com os resultados das execuções"""
    from gera_variantes import parse_code, gerar_hash_codigo_logico
    
    # Define as colunas necessárias
    colunas = [
        "codigo_original", "codigo_modificado", "codigo_modificado_hash",
        "linhas_modificadas", "input_arquivo", "output", "Tempo de simulacao",
        "Tempo prof5", "Prof5_outputs", "metricas", "timestamp"
    ]
    
    if os.path.exists(config["parquet_file"]):
        df_db = pd.read_parquet(config["parquet_file"])
        # Adiciona colunas que possam estar faltando
        for col in colunas:
            if col not in df_db.columns:
                df_db[col] = None
    else:
        df_db = pd.DataFrame(columns=colunas)
    
    # Lê e processa o arquivo original primeiro
    with open(original_file, "r") as f:
        codigo_original = f.read()
        original_lines = codigo_original.splitlines()
    
    # Obtém o mapeamento físico->lógico do arquivo original
    _, __, original_physical_to_logical = parse_code(original_file)
    hash_original = gerar_hash_codigo_logico(original_lines, original_physical_to_logical)
    
    # Carrega os outputs existentes
    output, tempo_sim, tempo_prof5, prof5_outputs = load_outputs(hash_original, config)
    
    # Verifica se já existe uma entrada para este hash
    mask = df_db['codigo_modificado_hash'] == hash_original
    if len(mask) != len(df_db):
        logging.error(f"Erro de dimensão: máscara tem {len(mask)} elementos, DataFrame tem {len(df_db)} linhas")
        print(f"Tamanho do DataFrame: {len(df_db)}")
        print(f"Tamanho da máscara: {len(mask)}")
        return None
    
    if mask.any():
        # Se existe, atualiza apenas os campos que têm novos dados
        row = df_db.loc[mask].iloc[0]
        if output is not None and (pd.isna(row['output']) or not row['output']):
            df_db.loc[mask, 'output'] = output
        if tempo_sim is not None and (pd.isna(row['Tempo de simulacao']) or not row['Tempo de simulacao']):
            df_db.loc[mask, 'Tempo de simulacao'] = tempo_sim
        if tempo_prof5 is not None and (pd.isna(row['Tempo prof5']) or not row['Tempo prof5']):
            df_db.loc[mask, 'Tempo prof5'] = tempo_prof5
        if prof5_outputs is not None:
            # Converte para dicionário se não for
            if not isinstance(prof5_outputs, dict):
                prof5_dict = {"data": prof5_outputs}
            else:
                prof5_dict = prof5_outputs
            
            df_db.loc[mask, 'Prof5_outputs'] = prof5_dict
            logging.info(f"Prof5 outputs atualizados para versão original")
    else:
        # Se não existe, cria uma nova entrada
        nova_execucao = {
            "codigo_original": os.path.basename(original_file),
            "codigo_modificado": os.path.basename(original_file),
            "codigo_modificado_hash": hash_original,
            "linhas_modificadas": "[]",
            "input_arquivo": config["train_data"],
            "output": output,
            "Tempo de simulacao": tempo_sim,
            "Tempo prof5": tempo_prof5,
            "metricas": {"mape": 0.0},
            "timestamp": datetime.now().isoformat()
        }
        df_db = pd.concat([df_db, pd.DataFrame([nova_execucao])], ignore_index=True)
        if prof5_outputs is not None:
            logging.info(f"Prof5 outputs adicionados para versão original")
    
    # Processa as variantes
    for variant_file in glob.glob(os.path.join(config["input_dir"], "kinematics_*.cpp")):
        if variant_file == original_file:
            continue
            
        with open(variant_file, "r") as f:
            codigo_modificado = f.read()
            modified_lines = codigo_modificado.splitlines()
        
        # Obtém as linhas modificadas comparando o código lógico
        linhas_modificadas = get_modified_logical_lines(original_lines, modified_lines, original_physical_to_logical)
        
        # Gera o hash do código modificado
        _, __, variant_physical_to_logical = parse_code(variant_file)
        hash_modificado = gerar_hash_codigo_logico(modified_lines, variant_physical_to_logical)
        
        # Carrega os outputs existentes
        output, tempo_sim, tempo_prof5, prof5_outputs = load_outputs(hash_modificado, config)
        
        # Verifica se já existe uma entrada para este hash
        mask = df_db['codigo_modificado_hash'] == hash_modificado
        if mask.any():
            # Se existe, atualiza apenas os campos que têm novos dados
            row = df_db.loc[mask].iloc[0]
            if output is not None and (pd.isna(row['output']) or not row['output']):
                df_db.loc[mask, 'output'] = output
            if tempo_sim is not None and (pd.isna(row['Tempo de simulacao']) or not row['Tempo de simulacao']):
                df_db.loc[mask, 'Tempo de simulacao'] = tempo_sim
            if tempo_prof5 is not None and (pd.isna(row['Tempo prof5']) or not row['Tempo prof5']):
                df_db.loc[mask, 'Tempo prof5'] = tempo_prof5
            if prof5_outputs is not None:
                # Converte para dicionário se não for
                if not isinstance(prof5_outputs, dict):
                    prof5_dict = {"data": prof5_outputs}
                else:
                    prof5_dict = prof5_outputs
                
                df_db.loc[mask, 'Prof5_outputs'] = prof5_dict
                logging.info(f"Prof5 outputs atualizados para variante {hash_modificado[:8]}")
        else:
            # Se não existe, cria uma nova entrada
            nova_execucao = {
                "codigo_original": os.path.basename(original_file),
                "codigo_modificado": os.path.basename(variant_file),
                "codigo_modificado_hash": hash_modificado,
                "linhas_modificadas": str(linhas_modificadas),
                "input_arquivo": config["train_data_input"],
                "output": output,
                "Tempo de simulacao": tempo_sim,
                "Tempo prof5": tempo_prof5,
                "Prof5_outputs": {},
                "timestamp": datetime.now().isoformat()
            }
            df_db = pd.concat([df_db, pd.DataFrame([nova_execucao])], ignore_index=True)
            if prof5_outputs is not None:
                logging.info(f"Prof5 outputs adicionados para variante {hash_modificado[:8]}")
    
    # Antes de salvar, normalize a coluna Prof5_outputs
    def normalize_prof5_output(value):
        """Normaliza os valores de Prof5_outputs para garantir consistência"""
        # Dicionário padrão com um campo dummy para evitar erro do Parquet
        default_dict = {"all": {"_dummy": None}}
        
        if pd.isna(value) or value is None:
            return default_dict
        
        # Se é uma lista aninhada, descompacta até o primeiro nível não-lista
        if isinstance(value, list):
            # Descompacta listas aninhadas
            while isinstance(value, list) and len(value) == 1 and isinstance(value[0], list):
                value = value[0]
            
            # Se a lista está vazia, retorna o dicionário padrão
            if not value:
                return default_dict
                
            # Se a lista contém arrays NumPy, converte para lista
            if len(value) > 0 and hasattr(value[0], 'tolist'):
                value = [item.tolist() if hasattr(item, 'tolist') else item for item in  value]
            
            # Retorna como dicionário com a chave 'all'
            return {"all": value}
        
        # Se é um array NumPy, converte para lista
        if hasattr(value, 'tolist'):
            return {"all": value.tolist()}
        
        # Se já é um dicionário
        if isinstance(value, dict):
            # Se não tem a chave 'all', adiciona
            if 'all' not in value:
                value = {"all": value}
            
            # Se 'all' está vazio, adiciona um campo dummy
            if not value['all']:
                value['all'] = {"_dummy": None}
            
            return value
        
        # Qualquer outro caso
        return default_dict
    
    # Aplica a normalização em todo o DataFrame
    df_db['Prof5_outputs'] = df_db['Prof5_outputs'].apply(normalize_prof5_output)
    
    # Reseta o índice antes de salvar
    df_db = df_db.reset_index(drop=True)
    
    # Use um arquivo temporário para salvar
    temp_file = "temp_execucoes.parquet"
    try:
        # Verifica se há dados antes de salvar
        if len(df_db) > 0:
            df_db.to_parquet(temp_file, index=False)
            os.chmod(temp_file, 0o666)
            os.replace(temp_file, config["parquet_file"])
            
            # Verifica se salvou corretamente
            df_check = pd.read_parquet(config["parquet_file"])
            print(f"Banco atualizado com sucesso. Total de entradas: {len(df_check)}")
            # Força um flush do sistema de arquivos
            os.sync()
        else:
            print("DataFrame vazio, nada para salvar")
    except Exception as e:
        print(f"Erro ao salvar o banco: {e}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return None
    
    return df_db

# --------------------------------------------------
# FUNÇÃO QUE CALCULA O MAPE E ATUALIZA O BANCO
# --------------------------------------------------
def compute_metrics(parquet_file):
    def parse_output(output_str):
        try:
            if not output_str or output_str == "Arquivo não gerado":
                return None
            numbers = [float(x) for x in output_str.split()]
            return np.array(numbers)
        except Exception as e:
            logging.error(f"Erro ao converter output: {output_str}")
            return None

    def compute_mape(y_true, y_pred):
        y_true = np.array(y_true)
        y_pred = np.array(y_pred)
        mask = y_true != 0
        if not np.any(mask):
            return None
        return np.mean(np.abs((y_true[mask] - y_pred[mask]) / y_true[mask])) * 100

    if not os.path.exists(parquet_file):
        logging.error(f"Arquivo {parquet_file} não encontrado.")
        return
    
    df = pd.read_parquet(parquet_file)
    
    # Procura pela versão original no banco
    orig_rows = df[df['linhas_modificadas'] == "[]"]
    if orig_rows.empty:
        logging.error("Nenhuma entrada original encontrada no banco de dados.")
        return
    
    # Pega o hash e output do código original do banco
    orig_row = orig_rows.iloc[0]
    original_hash = orig_row['codigo_modificado_hash']
    orig_output = orig_row['output']
    
    # Primeiro tenta ler do arquivo, se não conseguiu ler do arquivo ou deu erro no parse, tenta usar o banco
    orig_values = None
    orig_output_path = os.path.join("outputs", f"kinematics_{original_hash}.data")
    
    if os.path.exists(orig_output_path):
        with open(orig_output_path, "r") as f:
            orig_output_str = f.read().strip()
            orig_values = parse_output(orig_output_str)
    
    # Se não conseguiu ler do arquivo ou deu erro no parse, tenta usar o banco
    if orig_values is None:
        orig_values = parse_output(orig_output)
        if orig_values is None:
            logging.error("Não foi possível obter os valores originais nem do arquivo nem do banco.")
            return
    
    if 'metricas' not in df.columns:
        df['metricas'] = None
    
    # Atualiza as métricas para todas as variantes
    for idx, row in df.iterrows():
        if row['linhas_modificadas'] == "[]":
            df.at[idx, 'metricas'] = {"mape": 0.0}
            continue
        
        variant_values = None
        
        # Primeiro tenta ler do arquivo
        variant_hash = row['codigo_modificado_hash']
        variant_output_path = os.path.join("outputs", f"kinematics_{variant_hash}.data")
        
        if os.path.exists(variant_output_path):
            with open(variant_output_path, "r") as f:
                variant_output_str = f.read().strip()
                variant_values = parse_output(variant_output_str)
        
        # Se não conseguiu ler do arquivo ou deu erro no parse, tenta usar o banco
        if variant_values is None:
            variant_values = parse_output(row['output'])
        
        if variant_values is None:
            df.at[idx, 'metricas'] = {"mape": None}
            logging.warning(f"Não foi possível calcular MAPE para variante {row['codigo_modificado'][:8]}: dados ausentes ou inválidos")
            continue
        
        mape_value = compute_mape(orig_values, variant_values)
        df.at[idx, 'metricas'] = {"mape": mape_value}
        logging.info(f"MAPE calculado para variante {row['codigo_modificado'][:8]}: {mape_value:.2f}%")
    
    # Salva o DataFrame atualizado
    temp_file = "temp_execucoes.parquet"
    df.to_parquet(temp_file, index=False)
    os.chmod(temp_file, 0o666)
    os.replace(temp_file, parquet_file)
    logging.info("MAPE calculado e salvo no banco de dados.")

def force_compute_mape(parquet_file):
    """
    Força o cálculo do MAPE para todas as variantes e garante que seja salvo no banco.
    Esta função lida com problemas de dimensão e outros erros comuns.
    """
    print("Iniciando cálculo forçado de MAPE...")
    
    if not os.path.exists(parquet_file):
        print(f"Arquivo {parquet_file} não encontrado.")
        return False
    
    try:
        # Carrega o banco de dados
        df = pd.read_parquet(parquet_file)
        df = df.reset_index(drop=True)
        
        # Procura pela versão original no banco
        orig_rows = df[df['linhas_modificadas'] == "[]"]
        if orig_rows.empty:
            print("Nenhuma entrada original encontrada no banco de dados.")
            return False
        
        # Pega o output do código original
        orig_row = orig_rows.iloc[0]
        orig_output = orig_row['output']
        
        # Converte o output original para números
        try:
            if not orig_output or orig_output == "Arquivo não gerado" or "Arquivo" in orig_output:
                print("Output original não encontrado ou inválido.")
                return False
            
            # Tenta converter para números, ignorando linhas que não são números
            orig_values = []
            for x in orig_output.split():
                try:
                    orig_values.append(float(x))
                except ValueError:
                    continue
            
            if not orig_values:
                print("Não foi possível extrair valores numéricos do output original.")
                return False
                
            orig_values = np.array(orig_values)
            print(f"Output original convertido com sucesso. Tamanho: {len(orig_values)}")
        except Exception as e:
            print(f"Erro ao converter output original: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Inicializa a coluna de métricas
        if 'metricas' not in df.columns:
            df['metricas'] = [{"mape": None} for _ in range(len(df))]
        
        # Garante que todas as entradas de métricas sejam dicionários
        for idx in range(len(df)):
            if pd.isna(df.at[idx, 'metricas']) or df.at[idx, 'metricas'] is None:
                df.at[idx, 'metricas'] = {"mape": None}
        
        # Normaliza Prof5_outputs
        def normalize_prof5_output(value):
            """Normaliza os valores de Prof5_outputs para garantir consistência"""
            # Dicionário padrão com um campo dummy para evitar erro do Parquet
            default_dict = {"all": {"_dummy": None}}
            
            if pd.isna(value) or value is None:
                return default_dict
            
            # Se é uma lista aninhada, descompacta até o primeiro nível não-lista
            if isinstance(value, list):
                # Descompacta listas aninhadas
                while isinstance(value, list) and len(value) == 1 and isinstance(value[0], list):
                    value = value[0]
                
                # Se a lista está vazia, retorna o dicionário padrão
                if not value:
                    return default_dict
                    
                # Se a lista contém arrays NumPy, converte para lista
                if len(value) > 0 and hasattr(value[0], 'tolist'):
                    value = [item.tolist() if hasattr(item, 'tolist') else item for item in value]
                
                # Retorna como dicionário com a chave 'all'
                return {"all": value}
            
            # Se é um array NumPy, converte para lista
            if hasattr(value, 'tolist'):
                return {"all": value.tolist()}
            
            # Se já é um dicionário
            if isinstance(value, dict):
                # Se não tem a chave 'all', adiciona
                if 'all' not in value:
                    value = {"all": value}
                
                # Se 'all' está vazio, adiciona um campo dummy
                if not value['all']:
                    value['all'] = {"_dummy": None}
                
                return value
            
            # Qualquer outro caso
            return default_dict
        
        # Aplica a normalização em Prof5_outputs
        df['Prof5_outputs'] = df['Prof5_outputs'].apply(normalize_prof5_output)
        
        # Contador para acompanhamento
        total_variants = len(df)
        processed = 0
        success = 0
        failed = 0
        
        # Processa cada variante
        for idx, row in df.iterrows():
            processed += 1
            if processed % 100 == 0:
                print(f"Processando variante {processed}/{total_variants}")
            
            # Versão original tem MAPE 0
            if row['linhas_modificadas'] == "[]":
                df.at[idx, 'metricas'] = {"mape": 0.0}
                success += 1
                continue
            
            # Pula se não tiver output ou se o output for inválido
            if (pd.isna(row['output']) or not row['output'] or 
                row['output'] == "Arquivo não gerado" or "Arquivo" in row['output']):
                df.at[idx, 'metricas'] = {"mape": None}
                failed += 1
                continue
            
            # Tenta calcular o MAPE
            try:
                # Converte o output da variante para números, ignorando valores não numéricos
                variant_output = row['output']
                variant_values = []
                for x in variant_output.split():
                    try:
                        variant_values.append(float(x))
                    except ValueError:
                        continue
                
                if not variant_values:
                    print(f"Não foi possível extrair valores numéricos para variante {row['codigo_modificado_hash'][:8]}")
                    df.at[idx, 'metricas'] = {"mape": None}
                    failed += 1
                    continue
                    
                variant_values = np.array(variant_values)
                
                # Verifica se os arrays têm o mesmo tamanho
                if len(orig_values) != len(variant_values):
                    print(f"Aviso: Dimensões diferentes para variante {row['codigo_modificado_hash'][:8]}")
                    print(f"  Original: {len(orig_values)}, Variante: {len(variant_values)}")
                    
                    # Trunca para o menor tamanho
                    min_size = min(len(orig_values), len(variant_values))
                    orig_values_truncated = orig_values[:min_size]
                    variant_values_truncated = variant_values[:min_size]
                    
                    print(f"  Arrays truncados para tamanho {min_size}")
                else:
                    orig_values_truncated = orig_values
                    variant_values_truncated = variant_values
                
                # Calcula o MAPE
                mask = orig_values_truncated != 0
                if not np.any(mask):
                    print(f"Aviso: Todos os valores originais são zero para variante {row['codigo_modificado_hash'][:8]}")
                    df.at[idx, 'metricas'] = {"mape": None}
                    failed += 1
                    continue
                
                mape = np.mean(np.abs((orig_values_truncated[mask] - variant_values_truncated[mask]) / orig_values_truncated[mask])) * 100
                
                # Salva o MAPE no DataFrame
                df.at[idx, 'metricas'] = {"mape": float(mape)}
                print(f"MAPE calculado para variante {row['codigo_modificado_hash'][:8]}: {mape:.2f}%")
                success += 1
                
                # Salva o banco a cada 100 variantes processadas para evitar perda de dados
                if processed % 100 == 0:
                    temp_file = "temp_execucoes.parquet"
                    df.to_parquet(temp_file, index=False)
                    os.chmod(temp_file, 0o666)
                    os.replace(temp_file, parquet_file)
                    print(f"Banco salvo após processar {processed} variantes")
                
            except Exception as e:
                print(f"Erro ao calcular MAPE para variante {row['codigo_modificado_hash'][:8]}: {e}")
                import traceback
                traceback.print_exc()
                df.at[idx, 'metricas'] = {"mape": None}
                failed += 1
        
        # Salva o DataFrame final
        temp_file = "temp_execucoes.parquet"
        df.to_parquet(temp_file, index=False)
        os.chmod(temp_file, 0o666)
        os.replace(temp_file, parquet_file)
        
        print(f"MAPE calculado e salvo. Sucesso: {success}, Falhas: {failed}, Total: {total_variants}")
        
        # Verifica se o banco foi atualizado corretamente
        try:
            df_check = pd.read_parquet(parquet_file)
            mape_count = sum(1 for m in df_check['metricas'] if m is not None and isinstance(m, dict) and 'mape' in m and m['mape'] is not None)
            print(f"Verificação: {mape_count} variantes com MAPE calculado no banco")
            
            # Verifica Prof5_outputs
            prof5_types = {}
            for p in df_check['Prof5_outputs']:
                tipo = type(p).__name__
                if tipo not in prof5_types:
                    prof5_types[tipo] = 0
                prof5_types[tipo] += 1
            
            print(f"Tipos de Prof5_outputs: {prof5_types}")
            
            # Mostra alguns exemplos de MAPE calculados
            mape_examples = []
            for idx, row in df_check.iterrows():
                if (row['metricas'] is not None and isinstance(row['metricas'], dict) and 
                    'mape' in row['metricas'] and row['metricas']['mape'] is not None):
                    mape_examples.append((row['codigo_modificado_hash'][:8], row['metricas']['mape']))
                    if len(mape_examples) >= 5:
                        break
            
            print("Exemplos de MAPE calculados:")
            for hash_val, mape in mape_examples:
                print(f"  Variante {hash_val}: MAPE = {mape:.2f}%")
            
            # Mostra alguns exemplos de Prof5_outputs
            prof5_examples = []
            for idx, row in df_check.iterrows():
                if row['Prof5_outputs'] is not None and isinstance(row['Prof5_outputs'], dict):
                    prof5_examples.append((row['codigo_modificado_hash'][:8], row['Prof5_outputs']))
                    if len(prof5_examples) >= 3:
                        break
            
            print("Exemplos de Prof5_outputs:")
            for hash_val, prof5 in prof5_examples:
                print(f"  Variante {hash_val}: {type(prof5).__name__} com chaves {list(prof5.keys())}")
                if 'all' in prof5 and prof5['all']:
                    if isinstance(prof5['all'], dict):
                        print(f"    'all' contém {len(prof5['all'])} campos")
                        # Mostra algumas chaves de exemplo
                        sample_keys = list(prof5['all'].keys())[:3]
                        print(f"    Exemplos de chaves: {sample_keys}")
                    else:
                        print(f"    'all' é do tipo {type(prof5['all']).__name__}")
            
        except Exception as e:
            print(f"Erro ao verificar banco após cálculo de MAPE: {e}")
            import traceback
            traceback.print_exc()
        
        return True
        
    except Exception as e:
        print(f"Erro ao calcular MAPE: {e}")
        import traceback
        traceback.print_exc()
        return False

def clean_database(parquet_file):
    """Limpa e normaliza o banco de dados existente"""
    if not os.path.exists(parquet_file):
        return
        
    try:
        df = pd.read_parquet(parquet_file)
        
        # Normaliza Prof5_outputs usando a função melhorada
        def normalize_prof5_output(value):
            """Normaliza os valores de Prof5_outputs para garantir consistência"""
            # Dicionário padrão com um campo dummy para evitar erro do Parquet
            default_dict = {"all": {"_dummy": None}}
            
            if pd.isna(value) or value is None:
                return default_dict
            
            # Se é uma lista aninhada, descompacta até o primeiro nível não-lista
            if isinstance(value, list):
                # Descompacta listas aninhadas
                while isinstance(value, list) and len(value) == 1 and isinstance(value[0], list):
                    value = value[0]
                
                # Se a lista está vazia, retorna o dicionário padrão
                if not value:
                    return default_dict
                    
                # Se a lista contém arrays NumPy, converte para lista
                if len(value) > 0 and hasattr(value[0], 'tolist'):
                    value = [item.tolist() if hasattr(item, 'tolist') else item for item in  value]
                
                # Retorna como dicionário com a chave 'all'
                return {"all": value}
            
            # Se é um array NumPy, converte para lista
            if hasattr(value, 'tolist'):
                return {"all": value.tolist()}
            
            # Se já é um dicionário
            if isinstance(value, dict):
                # Se não tem a chave 'all', adiciona
                if 'all' not in value:
                    value = {"all": value}
                
                # Se 'all' está vazio, adiciona um campo dummy
                if not value['all']:
                    value['all'] = {"_dummy": None}
                
                return value
            
            # Qualquer outro caso
            return default_dict
        
        df['Prof5_outputs'] = df['Prof5_outputs'].apply(normalize_prof5_output)
        
        # Inicializa a coluna de métricas se não existir
        if 'metricas' not in df.columns:
            df['metricas'] = None
            
        # Garante que todas as métricas sejam dicionários
        def fix_metrics(value):
            if pd.isna(value) or value is None:
                return {"mape": None}
            if isinstance(value, dict):
                return value
            return {"mape": None}
        
        df['metricas'] = df['metricas'].apply(fix_metrics)
        
        # Remove duplicatas
        df = df.sort_values('timestamp', ascending=True)
        df = df.drop_duplicates(subset=['codigo_modificado_hash'], keep='last')
        
        # Reseta o índice
        df = df.reset_index(drop=True)
        
        # Salva o banco limpo
        temp_file = "temp_execucoes.parquet"
        df.to_parquet(temp_file, index=False)
        os.chmod(temp_file, 0o666)
        os.replace(temp_file, parquet_file)
        print(f"Banco de dados limpo e normalizado. Total de entradas: {len(df)}")
        
        # Verifica o banco limpo
        try:
            df_check = pd.read_parquet(parquet_file)
            mape_count = sum(1 for m in df_check['metricas'] if m is not None and isinstance(m, dict) and 'mape' in m and m['mape'] is not None)
            print(f"Verificação: {mape_count} variantes com MAPE calculado no banco")
            
            # Verifica Prof5_outputs
            prof5_types = {}
            for p in df_check['Prof5_outputs']:
                tipo = type(p).__name__
                if tipo not in prof5_types:
                    prof5_types[tipo] = 0
                prof5_types[tipo] += 1
            
            print(f"Tipos de Prof5_outputs: {prof5_types}")
        except Exception as e:
            print(f"Erro ao verificar banco após limpeza: {e}")
        
    except Exception as e:
        print(f"Erro ao limpar banco de dados: {e}")
        import traceback
        traceback.print_exc()

def fix_database_for_metrics(parquet_file):
    """Corrige problemas no banco de dados que impedem o cálculo de métricas"""
    if not os.path.exists(parquet_file):
        return False
    
    try:
        df = pd.read_parquet(parquet_file)
        
        # Normaliza Prof5_outputs usando a função melhorada
        def normalize_prof5_output(value):
            """Normaliza os valores de Prof5_outputs para garantir consistência"""
            # Dicionário padrão com um campo dummy para evitar erro do Parquet
            default_dict = {"all": {"_dummy": None}}
            
            if pd.isna(value) or value is None:
                return default_dict
            
            # Se é uma lista aninhada, descompacta até o primeiro nível não-lista
            if isinstance(value, list):
                # Descompacta listas aninhadas
                while isinstance(value, list) and len(value) == 1 and isinstance(value[0], list):
                    value = value[0]
                
                # Se a lista está vazia, retorna o dicionário padrão
                if not value:
                    return default_dict
                    
                # Se a lista contém arrays NumPy, converte para lista
                if len(value) > 0 and hasattr(value[0], 'tolist'):
                    value = [item.tolist() if hasattr(item, 'tolist') else item for item in  value]
                
                # Retorna como dicionário com a chave 'all'
                return {"all": value}
            
            # Se é um array NumPy, converte para lista
            if hasattr(value, 'tolist'):
                return {"all": value.tolist()}
            
            # Se já é um dicionário
            if isinstance(value, dict):
                # Se não tem a chave 'all', adiciona
                if 'all' not in value:
                    value = {"all": value}
                
                # Se 'all' está vazio, adiciona um campo dummy
                if not value['all']:
                    value['all'] = {"_dummy": None}
                
                return value
            
            # Qualquer outro caso
            return default_dict
        
        # Aplica a normalização
        df['Prof5_outputs'] = df['Prof5_outputs'].apply(normalize_prof5_output)
        
        # Inicializa a coluna de métricas se não existir
        if 'metricas' not in df.columns:
            df['metricas'] = None
        
        # Garante que todas as métricas sejam dicionários
        def fix_metrics(value):
            if pd.isna(value) or value is None:
                return {"mape": None}
            if isinstance(value, dict):
                return value
            return {"mape": None}
        
        df['metricas'] = df['metricas'].apply(fix_metrics)
        
        # Reseta o índice
        df = df.reset_index(drop=True)
        
        # Salva o banco corrigido
        temp_file = "temp_execucoes.parquet"
        df.to_parquet(temp_file, index=False)
        os.chmod(temp_file, 0o666)
        os.replace(temp_file, parquet_file)
        print(f"Banco corrigido para cálculo de métricas. Total de entradas: {len(df)}")
        
        # Verifica o banco corrigido
        try:
            df_check = pd.read_parquet(parquet_file)
            mape_count = sum(1 for m in df_check['metricas'] if m is not None and isinstance(m, dict) and 'mape' in m and m['mape'] is not None)
            print(f"Verificação: {mape_count} variantes com MAPE calculado no banco")
            
            # Verifica Prof5_outputs
            prof5_types = {}
            for p in df_check['Prof5_outputs']:
                tipo = type(p).__name__
                if tipo not in prof5_types:
                    prof5_types[tipo] = 0
                prof5_types[tipo] += 1
            
            print(f"Tipos de Prof5_outputs: {prof5_types}")
        except Exception as e:
            print(f"Erro ao verificar banco após correção: {e}")
        
        return True
        
    except Exception as e:
        print(f"Erro ao corrigir banco para métricas: {e}")
        import traceback
        traceback.print_exc()
        return False

def fix_everything(parquet_file):
    """
    Função abrangente para corrigir todos os problemas do banco de dados:
    1. Lê os arquivos JSON diretamente da pasta prof5Results
    2. Salva corretamente no banco com a estrutura adequada
    3. Calcula os valores de MAPE para todas as variantes
    """
    print("Iniciando correção completa do banco de dados...")
    
    if not os.path.exists(parquet_file):
        print(f"Arquivo {parquet_file} não encontrado.")
        return False
    
    try:
        # Carrega o banco de dados
        df = pd.read_parquet(parquet_file)
        df = df.reset_index(drop=True)
        
        # Inicializa a coluna de métricas se não existir
        if 'metricas' not in df.columns:
            df['metricas'] = [{"mape": None} for _ in range(len(df))]
        
        # Garante que todas as entradas de métricas sejam dicionários
        for idx in range(len(df)):
            if pd.isna(df.at[idx, 'metricas']) or df.at[idx, 'metricas'] is None:
                df.at[idx, 'metricas'] = {"mape": None}
        
        # Contador para acompanhamento
        total_variants = len(df)
        processed = 0
        prof5_success = 0
        prof5_dummy = 0
        mape_success = 0
        mape_failed = 0
        
        # Procura pela versão original no banco
        orig_rows = df[df['linhas_modificadas'] == "[]"]
        if orig_rows.empty:
            print("Nenhuma entrada original encontrada no banco de dados.")
            return False
        
        # Pega o output do código original
        orig_row = orig_rows.iloc[0]
        orig_hash = orig_row['codigo_modificado_hash']
        orig_output = orig_row['output']
        
        # Converte o output original para números
        try:
            if not orig_output or orig_output == "Arquivo não gerado" or "Arquivo" in orig_output:
                # Tenta ler o arquivo de output original diretamente
                orig_output_path = os.path.join("outputs", f"kinematics_{orig_hash}.data")
                if os.path.exists(orig_output_path):
                    with open(orig_output_path, 'r') as f:
                        orig_output = f.read().strip()
                        # Atualiza o banco com o output lido do arquivo
                        df.loc[df['codigo_modificado_hash'] == orig_hash, 'output'] = orig_output
                        print(f"Output original lido do arquivo: {orig_output_path}")
                else:
                    print("Output original não encontrado ou inválido.")
                    return False
            
            # Tenta converter para números, ignorando linhas que não são números
            orig_values = []
            for x in orig_output.split():
                try:
                    orig_values.append(float(x))
                except ValueError:
                    continue
            
            if not orig_values:
                print("Não foi possível extrair valores numéricos do output original.")
                return False
                
            orig_values = np.array(orig_values)
            print(f"Output original convertido com sucesso. Tamanho: {len(orig_values)}")
        except Exception as e:
            print(f"Erro ao converter output original: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        # Processa cada variante
        for idx, row in df.iterrows():
            processed += 1
            variant_hash = row['codigo_modificado_hash']
            
            # Atualiza Prof5_outputs lendo diretamente do arquivo JSON
            prof5_report_path = os.path.join("prof5Results", f"prof5_results_{variant_hash}.json")
            if os.path.exists(prof5_report_path):
                try:
                    with open(prof5_report_path, 'r') as f:
                        data = json.load(f)
                        # Cria um dicionário com a chave 'all' contendo os dados do Prof5
                        all_data = data.get('all', {})
                        # Se all_data estiver vazio, adiciona um campo dummy para evitar erro do Parquet
                        if not all_data:
                            all_data = {"_dummy": None}
                            prof5_dummy += 1
                        else:
                            prof5_success += 1
                        
                        df.at[idx, 'Prof5_outputs'] = {"all": all_data}
                        
                        if processed % 100 == 0 or processed == 1:
                            print(f"Processando variante {processed}/{total_variants}")
                            print(f"  Prof5 outputs lidos de {prof5_report_path}")
                            print(f"  Tipo: {type(all_data).__name__}, Tamanho: {len(all_data) if isinstance(all_data, dict) else 'N/A'}")
                except Exception as e:
                    print(f"Erro ao ler arquivo Prof5 {prof5_report_path}: {e}")
                    df.at[idx, 'Prof5_outputs'] = {"all": {"_dummy": None}}
                    prof5_dummy += 1
            else:
                # Se não encontrou o arquivo JSON, mantém o valor atual ou define um padrão
                if pd.isna(row['Prof5_outputs']) or row['Prof5_outputs'] is None:
                    df.at[idx, 'Prof5_outputs'] = {"all": {"_dummy": None}}
                    prof5_dummy += 1
                else:
                    # Normaliza o valor existente
                    current_value = row['Prof5_outputs']
                    if isinstance(current_value, dict):
                        if 'all' not in current_value:
                            current_value = {"all": current_value}
                        if not current_value['all']:
                            current_value['all'] = {"_dummy": None}
                            prof5_dummy += 1
                        else:
                            prof5_success += 1
                        df.at[idx, 'Prof5_outputs'] = current_value
                    else:
                        df.at[idx, 'Prof5_outputs'] = {"all": {"_dummy": None}}
                        prof5_dummy += 1
            
            # Versão original tem MAPE 0
            if row['linhas_modificadas'] == "[]":
                df.at[idx, 'metricas'] = {"mape": 0.0}
                mape_success += 1
                continue
            
            # Tenta ler o output da variante do arquivo se não estiver no banco ou for inválido
            variant_output = row['output']
            if (pd.isna(variant_output) or not variant_output or 
                variant_output == "Arquivo não gerado" or "Arquivo" in variant_output):
                variant_output_path = os.path.join("outputs", f"kinematics_{variant_hash}.data")
                if os.path.exists(variant_output_path):
                    with open(variant_output_path, 'r') as f:
                        variant_output = f.read().strip()
                        # Atualiza o banco com o output lido do arquivo
                        df.at[idx, 'output'] = variant_output
                        if processed % 100 == 0:
                            print(f"  Output lido do arquivo: {variant_output_path}")
            
            # Pula se ainda não tiver output or se o output for inválido
            if (pd.isna(variant_output) or not variant_output or 
                variant_output == "Arquivo não gerado" or "Arquivo" in variant_output):
                df.at[idx, 'metricas'] = {"mape": None}
                mape_failed += 1
                continue
            
            # Tenta calcular o MAPE
            try:
                # Converte o output da variante para números, ignorando valores não numéricos
                variant_values = []
                for x in variant_output.split():
                    try:
                        variant_values.append(float(x))
                    except ValueError:
                        continue
                
                if not variant_values:
                    if processed % 100 == 0:
                        print(f"  Não foi possível extrair valores numéricos para variante {variant_hash[:8]}")
                    df.at[idx, 'metricas'] = {"mape": None}
                    mape_failed += 1
                    continue
                    
                variant_values = np.array(variant_values)
                
                # Verifica se os arrays têm o mesmo tamanho
                if len(orig_values) != len(variant_values):
                    if processed % 100 == 0:
                        print(f"  Aviso: Dimensões diferentes para variante {variant_hash[:8]}")
                        print(f"    Original: {len(orig_values)}, Variante: {len(variant_values)}")
                    
                    # Trunca para o menor tamanho
                    min_size = min(len(orig_values), len(variant_values))
                    orig_values_truncated = orig_values[:min_size]
                    variant_values_truncated = variant_values[:min_size]
                    
                    if processed % 100 == 0:
                        print(f"    Arrays truncados para tamanho {min_size}")
                else:
                    orig_values_truncated = orig_values
                    variant_values_truncated = variant_values
                
                # Calcula o MAPE
                mask = orig_values_truncated != 0
                if not np.any(mask):
                    if processed % 100 == 0:
                        print(f"  Aviso: Todos os valores originais são zero para variante {variant_hash[:8]}")
                    df.at[idx, 'metricas'] = {"mape": None}
                    mape_failed += 1
                    continue
                
                mape = np.mean(np.abs((orig_values_truncated[mask] - variant_values_truncated[mask]) / orig_values_truncated[mask])) * 100
                
                # Salva o MAPE no DataFrame
                df.at[idx, 'metricas'] = {"mape": float(mape)}
                if processed % 100 == 0:
                    print(f"  MAPE calculado para variante {variant_hash[:8]}: {mape:.2f}%")
                mape_success += 1
                
            except Exception as e:
                if processed % 100 == 0:
                    print(f"  Erro ao calcular MAPE para variante {variant_hash[:8]}: {e}")
                df.at[idx, 'metricas'] = {"mape": None}
                mape_failed += 1
            
            # Salva o banco a cada 100 variantes processadas para evitar perda de dados
            if processed % 100 == 0:
                temp_file = "temp_execucoes.parquet"
                df.to_parquet(temp_file, index=False)
                os.chmod(temp_file, 0o666)
                os.replace(temp_file, parquet_file)
                print(f"Banco salvo após processar {processed} variantes")
        
        # Salva o DataFrame final
        temp_file = "temp_execucoes.parquet"
        df.to_parquet(temp_file, index=False)
        os.chmod(temp_file, 0o666)
        os.replace(temp_file, parquet_file)
        
        print("\nResumo da correção:")
        print(f"Total de variantes processadas: {total_variants}")
        print(f"Prof5_outputs com dados reais: {prof5_success}")
        print(f"Prof5_outputs com dados dummy: {prof5_dummy}")
        print(f"MAPE calculado com sucesso: {mape_success}")
        print(f"MAPE não calculado: {mape_failed}")
        
        # Verifica se o banco foi atualizado corretamente
        try:
            df_check = pd.read_parquet(parquet_file)
            mape_count = sum(1 for m in df_check['metricas'] if m is not None and isinstance(m, dict) and 'mape' in m and m['mape'] is not None)
            print(f"\nVerificação final: {mape_count} variantes com MAPE calculado no banco")
            
            # Verifica Prof5_outputs
            prof5_real = 0
            prof5_dummy = 0
            for p in df_check['Prof5_outputs']:
                if p is not None and isinstance(p, dict) and 'all' in p:
                    if p['all'] and not (len(p['all']) == 1 and '_dummy' in p['all']):
                        prof5_real += 1
                    else:
                        prof5_dummy += 1
            
            print(f"Prof5_outputs com dados reais: {prof5_real}")
            print(f"Prof5_outputs com dados dummy: {prof5_dummy}")
            
            # Mostra alguns exemplos de MAPE calculados
            mape_examples = []
            for idx, row in df_check.iterrows():
                if (row['metricas'] is not None and isinstance(row['metricas'], dict) and 
                    'mape' in row['metricas'] and row['metricas']['mape'] is not None):
                    mape_examples.append((row['codigo_modificado_hash'][:8], row['metricas']['mape']))
                    if len(mape_examples) >= 5:
                        break
            
            print("\nExemplos de MAPE calculados:")
            for hash_val, mape in mape_examples:
                print(f"  Variante {hash_val}: MAPE = {mape:.2f}%")
            
            # Mostra alguns exemplos de Prof5_outputs
            prof5_examples = []
            for idx, row in df_check.iterrows():
                if (row['Prof5_outputs'] is not None and isinstance(row['Prof5_outputs'], dict) and
                    'all' in row['Prof5_outputs'] and row['Prof5_outputs']['all'] and
                    not (len(row['Prof5_outputs']['all']) == 1 and '_dummy' in row['Prof5_outputs']['all'])):
                    prof5_examples.append((row['codigo_modificado_hash'][:8], row['Prof5_outputs']))
                    if len(prof5_examples) >= 3:
                        break
            
            print("\nExemplos de Prof5_outputs com dados reais:")
            for hash_val, prof5 in prof5_examples:
                print(f"  Variante {hash_val}: {type(prof5).__name__} com chaves {list(prof5.keys())}")
                if 'all' in prof5 and prof5['all']:
                    if isinstance(prof5['all'], dict):
                        print(f"    'all' contém {len(prof5['all'])} campos")
                        # Mostra algumas chaves de exemplo
                        sample_keys = list(prof5['all'].keys())[:3]
                        print(f"    Exemplos de chaves: {sample_keys}")
                    else:
                        print(f"    'all' é do tipo {type(prof5['all']).__name__}")
            
            print("\nCorreção completa finalizada com sucesso!")
            
        except Exception as e:
            print(f"Erro ao verificar banco após correção: {e}")
            import traceback
            traceback.print_exc()
        
        return True
        
    except Exception as e:
        print(f"Erro durante a correção completa: {e}")
        import traceback
        traceback.print_exc()
        return False

# Adicione esta função para verificar o conteúdo do banco após cada operação
def verify_database(parquet_file, message=""):
    """Verifica o conteúdo do banco de dados e imprime estatísticas"""
    try:
        if not os.path.exists(parquet_file):
            print(f"{message} - Banco de dados não encontrado: {parquet_file}")
            return
            
        df = pd.read_parquet(parquet_file)
        print(f"{message} - Estatísticas do banco:")
        print(f"  Total de entradas: {len(df)}")
        
        # Verifica métricas
        mape_count = sum(1 for m in df['metricas'] if m is not None and isinstance(m, dict) and 'mape' in m and m['mape'] is not None)
        print(f"  Entradas com MAPE calculado: {mape_count}")
        
        # Verifica Prof5_outputs
        prof5_count = sum(1 for p in df['Prof5_outputs'] if p is not None and p)
        print(f"  Entradas com Prof5_outputs: {prof5_count}")
        
        # Verifica tipos de Prof5_outputs
        prof5_types = {}
        for p in df['Prof5_outputs']:
            tipo = type(p).__name__
            if tipo not in prof5_types:
                prof5_types[tipo] = 0
            prof5_types[tipo] += 1
        
        print(f"  Tipos de Prof5_outputs: {prof5_types}")
        
    except Exception as e:
        print(f"{message} - Erro ao verificar banco: {str(e)}")

# --------------------------------------------------
# FUNÇÃO MAIN
# --------------------------------------------------
def main():
    global CONFIG
    stop_event = None
    
    try:
        # Configurar argumentos da linha de comando
        parser = argparse.ArgumentParser(description='Simulação e profiling de variantes')
        parser.add_argument('--semBanco', action='store_true', 
                            help='Executa simulação e profiling sem atualizar o banco de dados')
        # [Outros argumentos existentes...]
        args = parser.parse_args()
        
        # Configura o ambiente  
        setup_environment()
        
        # Na seção do --semBanco no método main() (por volta da linha 1880-1900):
        if args.semBanco:
            logging.info("Executando no modo sem banco de dados (--semBanco)")
            
            # Carrega as variantes já executadas
            executed_variants = load_executed_variants("executados.txt")
            logging.info(f"Carregadas {len(executed_variants)} variantes já executadas do arquivo executados.txt")
            
            # Lista para armazenar variantes a serem simuladas
            variants_to_simulate = []
            
            # Verifica o arquivo original
            with open(CONFIG["original_file"], "r") as f:
                original_lines = f.readlines()
            _, __, original_physical_to_logical = parse_code(CONFIG["original_file"])
            original_hash = gerar_hash_codigo_logico(original_lines, original_physical_to_logical)
            
            # Adiciona o arquivo original apenas se não constar no executados.txt
            if original_hash not in executed_variants:
                variants_to_simulate.append(CONFIG["original_file"])
                logging.info("Versão original será simulada.")
            else:
                logging.info(f"Versão original (hash {short_hash(original_hash)}) já executada, pulando.")
            
            # Para cada variante no diretório de entrada
            for file in glob.glob(os.path.join(CONFIG["input_dir"], "kinematics_*.cpp")):
                with open(file, "r") as f:
                    variant_lines = f.readlines()
                variant_hash = gerar_hash_codigo_logico(variant_lines, original_physical_to_logical)
                
                # Adiciona apenas se não constar no executados.txt
                if variant_hash not in executed_variants:
                    variants_to_simulate.append(file)
                    logging.info(f"Variante {os.path.basename(file)} (hash {short_hash(variant_hash)}) será simulada.")
                else:
                    logging.info(f"Variante {os.path.basename(file)} (hash {short_hash(variant_hash)}) já executada, pulando.")
            
            # Log com o total de variantes a serem simuladas
            logging.info(f"Total de {len(variants_to_simulate)} variantes a serem simuladas.")
            
            # Processa as variantes em paralelo
            max_workers = max(1, os.cpu_count() - 1)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(compilar_e_simular, file, CONFIG, True): file 
                         for file in variants_to_simulate}
                for future in as_completed(futures):
                    future.result()
            
            logging.info("Todas as simulações foram concluídas no modo sem banco.")
            sys.exit(0)
        
        
        # Limpa e normaliza o banco de dados existente
        if os.path.exists(CONFIG["parquet_file"]):
            clean_database(CONFIG["parquet_file"])
        
        # Verifica os argumentos da linha de comando
        if len(sys.argv) > 1:
            if sys.argv[1] == "--compute-mape":
                # Se a flag --compute-mape for passada, apenas calcula o MAPE usando dados do banco
                logging.info("Calculando MAPE usando apenas dados do banco...")
                if fix_database_for_metrics(CONFIG["parquet_file"]):
                    force_compute_mape(CONFIG["parquet_file"])
                else:
                    logging.error("Não foi possível corrigir o banco para calcular métricas")
                sys.exit(0)
            elif sys.argv[1] == "--force-mape":
                # Nova flag para forçar o cálculo do MAPE sem outras correções
                logging.info("Forçando cálculo do MAPE...")
                force_compute_mape(CONFIG["parquet_file"])
                sys.exit(0)
            elif sys.argv[1] == "--fix-everything":
                # Nova flag para corrigir todos os problemas de uma vez
                logging.info("Corrigindo todos os problemas do banco de dados...")
                fix_everything(CONFIG["parquet_file"])
                sys.exit(0)
            elif sys.argv[1] == "--atualizabanco":
                # Se a flag --atualizabanco for passada, apenas atualiza o banco com os arquivos existentes
                logging.info("Atualizando banco de dados com arquivos existentes...")
                # Cria diretórios necessários sem limpar
                for d in ["codigos_executaveis", "outputs", "codigos_modificados", "prof5Results", "dump"]:
                    os.makedirs(d, exist_ok=True)
                # Atualiza o banco sem fazer novas simulações
                df = update_database(CONFIG, CONFIG["original_file"], only_load_existing=True)
                if df is not None:
                    compute_metrics(CONFIG["parquet_file"])
                logging.info("Atualização do banco concluída.")
                sys.exit(0)
        
        # Antes de começar o processamento:
        if os.path.exists("execucoes.parquet"):
            os.rename("execucoes.parquet", "execucoes.parquet.bak")
            print("Backup do banco de dados criado")
        
        setup_environment()
       
        # Após setup_environment() e antes de montar a lista de variantes
        executed_variants = load_executed_variants()
        
        # Inicializa a lista de variantes a simular
        variants_to_simulate = []
        
        # Verifica a versão original
        with open(CONFIG["original_file"], "r") as f:
            original_lines = f.readlines()
        _, __, original_physical_to_logical = parse_code(CONFIG["original_file"])
        original_hash = gerar_hash_codigo_logico(original_lines, original_physical_to_logical)
        
        if original_hash not in executed_variants:
            variants_to_simulate.append(CONFIG["original_file"])
            logging.info("Versão original será simulada")
        else:
            logging.info("Versão original já executada, pulando")
        
        # Para cada variante, usando arquivos na pasta de modificados (aqui considere a extensão '.c' ou '.cpp' conforme seu padrão)
        for file in glob.glob(os.path.join(CONFIG["input_dir"], "kinematics_*.cpp")):
            with open(file, "r") as f:
                modified_lines = f.readlines()
            codigo_modificado_hash = gerar_hash_codigo_logico(modified_lines, original_physical_to_logical)
            if codigo_modificado_hash not in executed_variants:
                variants_to_simulate.append(file)
                logging.info(f"Variante {codigo_modificado_hash[:8]} será simulada")
            else:
                logging.info(f"Variante {codigo_modificado_hash[:8]} já executada, pulando")

        # Inicia a thread que exibe o status das variantes em tempo real
        stop_event = threading.Event()
        monitor_thread = threading.Thread(target=monitor_statuses, args=(stop_event,))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Carrega o DataFrame existente (se houver) e remove duplicatas
        df_existing = None
        if os.path.exists(CONFIG["parquet_file"]):
            df_existing = pd.read_parquet(CONFIG["parquet_file"])
            # Remove duplicatas mantendo a entrada mais recente de cada variante
            df_existing = df_existing.sort_values('timestamp', ascending=True)
            df_existing = df_existing.drop_duplicates(
                subset=['codigo_modificado_hash'],
                keep='last'
            )
            # Salva o DataFrame limpo
            df_existing.to_parquet(CONFIG["parquet_file"], index=False)
            logging.info("Banco de dados limpo de duplicatas.")
        
        # Faz o parse do arquivo original para obter as linhas e o mapeamento
        original_lines, modifiable_lines, original_physical_to_logical = parse_code(CONFIG["original_file"])
        
        # Lista para variantes que precisam de simulação
        variants_to_simulate = []
        
        # Primeiro verifica se precisa simular a versão original
        original_hash = gerar_hash_codigo_logico(original_lines, original_physical_to_logical)
        if df_existing is not None:
            original_entry = df_existing[df_existing['codigo_modificado_hash'] == original_hash]
            if original_entry.empty:
                variants_to_simulate.append(CONFIG["original_file"])
                logging.info("Versão original será simulada")
            else:
                # Verifica se os dados da versão original estão completos
                entry = original_entry.iloc[0]
                if (entry['output'] is None or
                    pd.isna(entry['output']) or
                    entry['output'].strip() in ["", "Arquivo não gerado"] or
                    pd.isna(entry['Tempo prof5']) or 
                    str(entry['Tempo prof5']).strip() == ""):
                    variants_to_simulate.append(CONFIG["original_file"])
                    logging.info("Versão original será simulada (dados incompletos)")
        else:
            variants_to_simulate.append(CONFIG["original_file"])
            logging.info("Versão original será simulada (banco vazio)")
        
        # Para cada arquivo de variante
        for file in glob.glob(os.path.join(CONFIG["input_dir"], "kinematics_*.cpp")):
            with open(file, "r") as f:
                modified_lines = f.readlines()
            modified_indices = get_modified_lines_physical(original_lines, modified_lines)
            linhas_modificadas_logicas = [original_physical_to_logical[idx] for idx in modified_indices if idx in original_physical_to_logical]
            linhas_modificadas_str = str(linhas_modificadas_logicas)
            codigo_modificado_hash = gerar_hash_codigo_logico(modified_lines, original_physical_to_logical)
            
            # Primeiro verifica se os arquivos de output existem e são válidos
            files_ok, reason = check_output_files(file, CONFIG)
            
            needs_reprocessing = False
            reasons = []
            
            if not files_ok:
                needs_reprocessing = True
                reasons.append(reason)
            
            # Se os arquivos existem, verifica se estão no banco
            if df_existing is not None and not needs_reprocessing:
                registro = df_existing[df_existing["codigo_modificado_hash"] == codigo_modificado_hash]
                if not registro.empty:
                    entry = registro.iloc[0]
                    if (entry['output'] is None or
                        pd.isna(entry['output']) or
                        entry['output'].strip() in ["", "Arquivo não gerado"] or
                        pd.isna(entry['Tempo prof5']) or 
                        str(entry['Tempo prof5']).strip() == ""):
                        needs_reprocessing = True
                        reasons.append("dados incompletos no banco")
                else:
                    needs_reprocessing = True
                    reasons.append("variante não encontrada no banco")
            else:
                needs_reprocessing = True
                reasons.append("variante não encontrada no banco")
            
            if needs_reprocessing:
                logging.info(f"Variante {os.path.basename(file)[:8]} será processada. Motivos: {', '.join(reasons)}")
                variants_to_simulate.append(file)
            else:
                logging.info(f"Variante {os.path.basename(file)[:8]} já processada completamente, pulando simulação.")
        
        # Se não há variantes para simulação, avisa e pula essa etapa
        if not variants_to_simulate:
            logging.info("Nenhuma variante necessita de simulação. Pulando execução.")
        else:
            # Processa as variantes em paralelo, utilizando (cpu_count - 1) workers
            max_workers = max(1, os.cpu_count() - 1)
            #max_workers = 30
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(compilar_e_simular, file, CONFIG): file for file in variants_to_simulate}
                for future in as_completed(futures):
                    future.result()
        
        logging.info("Todas as simulações foram concluídas.")
        
        # Atualiza o banco e calcula métricas
        update_database(CONFIG, CONFIG["original_file"])
        if fix_database_for_metrics(CONFIG["parquet_file"]):
            compute_metrics(CONFIG["parquet_file"])
        else:
            logging.error("Não foi possível corrigir o banco para calcular métricas")
        
        # Encerra o monitor e aguarda a thread terminar
        if stop_event:
            stop_event.set()
            monitor_thread.join(timeout=2)  # Espera no máximo 2 segundos
        
        logging.info("Programa finalizado com sucesso.")
        sys.exit(0)  # Encerra explicitamente o programa
        
    except Exception as e:
        logging.error(f"Erro durante a execução: {str(e)}")
        if stop_event:
            stop_event.set()  # Garante que a thread de monitoramento será encerrada
        sys.exit(1)  # Encerra com código de erro

if __name__ == '__main__':
    # Configuração do logging: grava em 'execucoes.log' e exibe na saída padrão.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler("execucoes.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    main()