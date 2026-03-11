import os
import glob
import re
import json
import logging
import shutil
from datetime import datetime

def ensure_dirs(*dirs):
    """Garante que os diretórios especificados existam"""
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        logging.info(f"Diretório '{d}' verificado/criado")

def copy_file(src, dest_dir):
    # Garante que o diretório de destino existe
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copy(src, dest_dir)
    return os.path.join(dest_dir, os.path.basename(src))

def get_modified_lines_physical(orig_lines, mod_lines):
    """Identifica as linhas fisicamente modificadas entre dois arquivos"""
    modified_indices = []
    size = min(len(orig_lines), len(mod_lines))
    for i in range(size):
        if orig_lines[i] != mod_lines[i]:
            modified_indices.append(i)
    if len(mod_lines) > size:
        modified_indices.extend(range(size, len(mod_lines)))
    return modified_indices

def extract_hash_from_filename(filename):
    """Extrai o hash de um nome de arquivo no formato 'prefixo_hash.extensão'"""
    parts = filename.split('_')
    if len(parts) > 1:
        return parts[-1].split('.')[0]
    return None

def short_hash(hash_value, length=8):
    """Retorna uma versão curta do hash para exibição em logs"""
    return hash_value[:length] if isinstance(hash_value, str) else ""

def move_processed_files(hash_prefix, source_folders, dest_folder):
    """Move os arquivos processados para uma pasta específica"""
    os.makedirs(dest_folder, exist_ok=True)
    
    moved_files = 0
    for folder in source_folders:
        pattern = os.path.join(folder, f"*{hash_prefix}*")
        for file in glob.glob(pattern):
            destination = os.path.join(dest_folder, os.path.basename(file))
            shutil.move(file, destination)
            moved_files += 1
    
    if moved_files > 0:
        logging.info(f"Movidos {moved_files} arquivos relacionados à variante {hash_prefix[:8]} para {dest_folder}")
    
    return moved_files

class TempFiles:
    """Gerenciador de contexto para garantir limpeza de arquivos temporários"""
    def __init__(self, files):
        self.files = files
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        for file in self.files:
            if os.path.exists(file):
                try:
                    os.chmod(file, 0o666)
                    os.remove(file)
                    logging.debug(f"Arquivo temporário removido: {file}")
                except Exception as e:
                    logging.warning(f"Não foi possível remover {file}: {e}")

def generate_report(data, config):
    """Gera um relatório detalhado da execução"""
    import json
    from datetime import datetime
    
    report_file = os.path.join(config["outputs_dir"], f"execution_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    # Adiciona informações adicionais ao relatório
    report_data = {
        **data,
        "timestamp": datetime.now().isoformat(),
        "config": {k: v for k, v in config.items() if isinstance(v, (str, int, float, bool))}
    }
    
    with open(report_file, "w") as f:
        json.dump(report_data, f, indent=2)
    
    logging.info(f"Relatório de execução gerado em {report_file}")
    return report_file

def save_checkpoint(processed_count, total_variants, processed_hashes, config):
    """Salva o estado atual da execução"""
    checkpoint_file = config.get("checkpoint_file") or os.path.join(config["logs_dir"], "checkpoint.json")
    
    try:
        checkpoint_data = {
            "processed": processed_count,
            "total": total_variants,
            "variant_hashes": list(processed_hashes)
        }
        
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint_data, f, indent=2)
        
        logging.info(f"Checkpoint salvo: {processed_count} de {total_variants} variantes processadas")
        return True
    except Exception as e:
        logging.error(f"Erro ao salvar checkpoint: {e}")
        return False

def load_checkpoint(config):
    """Carrega o último checkpoint salvo"""
    checkpoint_file = config.get("checkpoint_file") or os.path.join(config["logs_dir"], "checkpoint.json")
    
    if not os.path.exists(checkpoint_file):
        return None, 0, 0
    
    try:
        with open(checkpoint_file, "r") as f:
            checkpoint_data = json.load(f)
        
        processed = checkpoint_data.get("processed", 0)
        total = checkpoint_data.get("total", 0)
        variant_hashes = checkpoint_data.get("variant_hashes", [])
        processed_variants = set(variant_hashes)
        
        return processed_variants, processed, total
    except Exception as e:
        logging.error(f"Erro ao carregar checkpoint: {e}")
        return None, 0, 0