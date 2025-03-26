import os

# Configurações do projeto
CONFIG = {
    "input_file": "inversek2j/src/kinematics.cpp",
    "output_folder": "codigos_modificados",
    "executed_variants_file": "executados.txt",
    "operations_map": {'*': 'FMULX', '+': 'FADDX', '-': 'FSUBX'}
}

def get_config():
    return CONFIG.copy()

def update_config(new_config):
    global CONFIG
    CONFIG.update(new_config)