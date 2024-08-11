import re
import clang.cindex
import pandas as pd
from uuid import uuid4
from clang.cindex import Index, TranslationUnit


def extract_functions_from_file(c_code: str) -> pd.DataFrame:
    index = Index.create()
    filename = uuid4()

    tu = index.parse(f'{filename}.c',
                     unsaved_files=[(f'{filename}.c', c_code)],
                     args=['-std=c11'],
                     options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)

    code_lines = c_code.split('\n')
    c_functions = []

    def remove_comments(text):
        text = re.sub(r'//.*', '', text)
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        return text

    def escape_next_line(text):
        return re.sub(r'(".*?)\n(.*?")', r'\1\\n\2', text)

    def visit_node(node):
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL and node.is_definition():
            function_name = node.spelling
            start_line, end_line = node.extent.start.line, node.extent.end.line

            function_content = code_lines[start_line - 1:end_line]

            function_content = remove_comments('\n'.join(function_content))
            # function_content = escape_next_line(function_content)
            function_content = '\n'.join(line for line in function_content.split('\n') if line.strip())

            c_functions.append((function_name, function_content))

        for child in node.get_children():
            visit_node(child)

    visit_node(tu.cursor)
    if len(c_functions) == 0:
        return pd.DataFrame(columns=['function_name', 'function_content'])

    if len(c_functions) == 1:
        return pd.DataFrame(c_functions, columns=['function_name', 'function_content'])

    return pd.DataFrame(c_functions, columns=['function_name', 'function_content'])
