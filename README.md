# Projeto de Análise de Computação Aproximada

Este projeto implementa um framework para análise de variantes de código aproximado, permitindo a geração automática de variantes, compilação, simulação e análise de desempenho em arquitetura RISC-V.

## Estrutura do Projeto

```
PaCA/
├── src/                    # Código-fonte principal
│   ├── apps/               # Aplicações suportadas
│   ├── database/           # Módulos de persistência
│   ├── execution/          # Módulos de execução e simulação
│   └── utils/              # Utilitários comuns
├── data/                   # Dados de referência
│   └── reference/          # Arquivos de configuração e referência
├── storage/                # Diretório para armazenamento de resultados
│   ├── dump/               # Dumps de código objeto
│   ├── executable/         # Executáveis compilados
│   ├── logs/               # Logs de execução
│   ├── output/             # Saídas das simulações
│   └── prof5_results/      # Resultados do profiler Prof5
└── codigos_modificados/    # Variantes de código geradas
```

## Requisitos

- Sistema operacional compatível com RISC-V toolchain (Linux recomendado)
- RISC-V GNU Toolchain (específico para rv32imafdc)
- Simulador Spike
- Prof5 (profiler especializado)
- Python 3.8+

## Configuração do Ambiente

1. Clone este repositório
2. Instale a toolchain RISC-V:
   ```
   # Exemplo para Ubuntu/Debian
   sudo apt install gcc-riscv64-unknown-elf
   ```
3. Instale o simulador Spike
4. Instale o Prof5 (siga as instruções no repositório do Prof5)
5. Configure os caminhos em `src/config_base.py` e `src/config.py`

## Como Executar

Para executar o sistema com uma aplicação específica:

```bash
cd mestrado
python src/run.py --app [nome_da_aplicacao] --workers [num_threads]
```

Onde:
- `[nome_da_aplicacao]` é o nome da aplicação a ser simulada
- `[num_threads]` é o número de threads a serem utilizadas para paralelização (opcional)

## Geração de Variantes

Para gerar variantes de código para uma aplicação:

```bash
python src/gera_variantes.py --input [arquivo_entrada] --output [pasta_saida]
```

## Como Adicionar Novas Aplicações

1. Crie um novo módulo em `src/apps/[nova_aplicacao].py`
2. Implemente as seguintes funções:
   - `prepare_environment(base_config)`
   - `generate_variants(base_config)`
   - `find_variants_to_simulate(base_config)`
   - `simulate_variant(variant_file, variant_hash, base_config, status_monitor)`
3. Adicione a aplicação ao dicionário `AVAILABLE_APPS` em `src/run.py`

## Arquivos de Controle

- `executados.txt`: Controla as variantes já executadas
- `falhas.txt`: Registra variantes que falharam durante a execução
- `checkpoint.txt`: Permite retomar a execução em caso de interrupção

## Estrutura de Transformações

As transformações são definidas por mapeamentos de operadores para funções aproximadas:

```python
OPERATIONS_MAP = {'*': 'FMULX', '+': 'FADDX', '-': 'FSUBX'}
```

As funções aproximadas são implementadas em `data/reference/approx.h`.

## Análise de Resultados

Os resultados de simulação são armazenados em:
- `storage/output/`: Dados de saída das simulações
- `storage/prof5_results/`: Resultados detalhados do profiler
- `storage/logs/`: Logs de execução para análise de erros

## Licença

Este projeto é parte de uma pesquisa acadêmica. Todos os direitos reservados.
