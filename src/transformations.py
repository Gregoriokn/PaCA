import re

def apply_transformation(line, operation_map):
    """
    Aplica transformações em uma linha de código substituindo operadores aritméticos
    por chamadas de função equivalentes.
    """
    # Padrão mais abrangente para capturar também chamadas de função
    operand = r'(?:\(-?[0-9\.]+\)|-?[\w\.]+(?:\([^\)]*\))?(?:f)?)'
    
    for op, func in operation_map.items():
        if op in line:
            # Escapar o operador para evitar problemas no regex
            escaped_op = re.escape(op)
            
            pattern = re.compile(
                r'(?P<before>(?:^|[\(=,\s]))'
                r'(?P<expr>(?!' + re.escape(func) + r'\()'
                r'(?:' + operand + r'(?:\s*' + escaped_op + r'\s*' + operand + r')+))'
                r'(?P<after>(?=[,\)\;])|\s*$)'
            )

            def sub_func(m):
                before = m.group("before")
                after = m.group("after")
                expr = m.group("expr")
                operands = re.split(r'\s*' + re.escape(op) + r'\s*', expr)
                result = operands[0]
                for opnd in operands[1:]:
                    result = f"{func}({result}, {opnd})"
                return f"{before}{result}{after}"

            new_line = line
            while True:
                new_line2 = pattern.sub(sub_func, new_line)
                if new_line2 == new_line:
                    break
                new_line = new_line2
            line = new_line
    
    return line