import os
import subprocess
import logging
from utils.file_utils import short_hash

def compile_variant(variant_file, variant_hash, config, status_monitor):
    """
    Compila uma variante de código para um objeto e um executável RISC-V.
    Retorna True se a compilação foi bem-sucedida, False caso contrário.
    """
    is_original = (variant_file == config["original_file"])
    variant_id = "original" if is_original else short_hash(variant_hash)
    
    # Atualiza o status
    status_monitor.update_status(variant_id, "Compilando")
    
    # Define os arquivos de saída
    exe_prefix = config.get("exe_prefix", "app_")
    obj_file = os.path.join(config["executables_dir"], f"{exe_prefix}{variant_hash}.o")
    exe_file = os.path.join(config["executables_dir"], f"{exe_prefix}{variant_hash}")
    
    # Comando de compilação genérico
    compile_cmd = [
        "riscv32-unknown-elf-g++",
        "-march=rv32imafdc",
        "-I", os.path.dirname(config["original_file"]),
        "-I", config["input_dir"],
        "-c", variant_file,
        "-o", obj_file,
        "-lm"
    ]
    
    # Executa a compilação
    try:
        result = subprocess.run(compile_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stderr:
            logging.info(f"[Variante {variant_id}] Avisos de compilação: {result.stderr.decode()}")
        logging.info(f"[Variante {variant_id}] Compilação do objeto concluída com sucesso")
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variante {variant_id}] Erro na compilação do objeto: {e.stderr.decode()}")
        status_monitor.update_status(variant_id, "Erro na compilação")
        return False
    
    # Comando de linkagem genérico
    link_cmd = [
        "riscv32-unknown-elf-g++",
        "-march=rv32imafdc",
        config.get("inversek2j_object", ""),  # Objeto específico da aplicação
        obj_file,
        "-o", exe_file,
        "-lm"
    ]
    
    # Executa a linkagem
    try:
        result = subprocess.run(link_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stderr:
            logging.info(f"[Variante {variant_id}] Avisos de linkagem: {result.stderr.decode()}")
        logging.info(f"[Variante {variant_id}] Linkagem concluída com sucesso")
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variante {variant_id}] Erro na linkagem: {e.stderr.decode()}")
        status_monitor.update_status(variant_id, "Erro na linkagem")
        return False
    
    # Define permissões do executável
    os.chmod(exe_file, 0o755)
    
    return True

def generate_dump(exe_file, dump_file, variant_id, status_monitor):
    """Gera o dump do código objeto compilado"""
    status_monitor.update_status(variant_id, "Gerando dump")
    
    dump_cmd = [
        "riscv32-unknown-elf-objdump",
        "-d",
        exe_file
    ]
    
    try:
        with open(dump_file, "w") as df:
            subprocess.run(dump_cmd, check=True, stdout=df, stderr=subprocess.PIPE)
        os.chmod(dump_file, 0o666)
        logging.info(f"[Variante {variant_id}] Dump gerado com sucesso: {dump_file}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"[Variante {variant_id}] Erro ao gerar dump: {e.stderr.decode()}")
        status_monitor.update_status(variant_id, "Erro no dump")
        return False