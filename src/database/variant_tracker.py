import os
import logging
import threading

class VariantCache:
    """Classe singleton para gerenciar o cache de variantes executadas"""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, file_path="executados.txt"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(VariantCache, cls).__new__(cls)
                cls._instance.file_path = file_path
                cls._instance.variants = set()
                cls._instance.file_lock = threading.Lock()
                cls._instance._load_cache()
            elif cls._instance.file_path != file_path:
                # Se o caminho mudou, recarrega o cache
                cls._instance.file_path = file_path
                cls._instance.variants.clear()
                cls._instance._load_cache()
        return cls._instance
    
    def _load_cache(self):
        """Carrega os hashes das variantes do arquivo para o cache"""
        if os.path.exists(self.file_path):
            with open(self.file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self.variants.add(line)
            logging.info(f"Cache inicializado com {len(self.variants)} variantes do arquivo {self.file_path}")
        else:
            logging.warning(f"Arquivo {self.file_path} não encontrado durante inicialização do cache!")
    
    def add_variant(self, codigo_hash):
        """Adiciona uma variante ao cache e ao arquivo de forma thread-safe"""
        # Verifica se a variante já está no cache
        if codigo_hash in self.variants:
            return False
        
        # Adiciona ao cache e ao arquivo de forma atômica
        with self.file_lock:
            # Verifica novamente para garantir que outra thread não adicionou 
            # enquanto estávamos esperando o lock
            if codigo_hash in self.variants:
                return False
                
            # Adiciona ao cache
            self.variants.add(codigo_hash)
            
            # Adiciona ao arquivo
            try:
                with open(self.file_path, "a") as f:
                    f.write(codigo_hash + "\n")
                logging.info(f"Variante {codigo_hash[:8]} adicionada ao arquivo {self.file_path}")
                return True
            except Exception as e:
                # Em caso de erro, remove do cache para manter consistência
                self.variants.remove(codigo_hash)
                logging.error(f"Erro ao adicionar variante {codigo_hash[:8]} ao arquivo: {e}")
                return False
    
    def contains(self, codigo_hash):
        """Verifica se uma variante está no cache"""
        return codigo_hash in self.variants
    
    def get_all_variants(self):
        """Retorna uma cópia do conjunto de variantes"""
        return self.variants.copy()


def load_executed_variants(file_path="executados.txt"):
    """Carrega os hashes das variantes já executadas a partir do cache"""
    cache = VariantCache(file_path)
    return cache.get_all_variants()


def add_executed_variant(codigo_hash, file_path="executados.txt"):
    """Adiciona o hash de uma variante executada no cache e no arquivo"""
    cache = VariantCache(file_path)
    return cache.add_variant(codigo_hash)


def is_variant_executed(codigo_hash, file_path="executados.txt"):
    """Verifica se uma variante já foi executada usando o cache"""
    cache = VariantCache(file_path)
    return cache.contains(codigo_hash)


def add_failed_variant(variant_hash, reason, file_path):
    """Registra uma variante que falhou junto com o motivo"""
    try:
        with open(file_path, "a") as f:
            f.write(f"{variant_hash},{reason}\n")
        logging.info(f"Variante com falha {variant_hash[:8]} registrada: {reason}")
        return True
    except Exception as e:
        logging.error(f"Erro ao registrar variante com falha {variant_hash[:8]}: {e}")
        return False