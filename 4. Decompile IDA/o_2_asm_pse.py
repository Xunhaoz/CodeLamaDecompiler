import idautils
import idc
import idaapi
import ida_auto
import ida_pro
from pathlib import Path
import ida_hexrays
import ida_funcs
import ida_name
import ida_idaapi
import ida_lines
import ida_auto
import ida_pro
import idautils
import idaapi
import idc

ida_auto.auto_wait()

def get_current_filename():
    filename = idaapi.get_input_file_path()
    return filename


def write_file(content, file_path):
    with open(file_path, 'w') as f:
        f.write(content)
    

def get_function_asm(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    
    if func_addr == idc.BADADDR:
        return
    
    func = idaapi.get_func(func_addr)
    if not func:
        return

    func_start, func_end = func.start_ea, func.end_ea

    asm_code = [f"{func_name} proc near\n"]
    
    for head in idautils.Heads(func_start, func_end):
        disasm_line = idc.generate_disasm_line(head, 0)
        
        if disasm_line:
            asm_code.append(disasm_line)

    return '\n'.join(asm_code + [f"{func_name} endp\n"])

    
def get_pseudocode(function_name):
    function_address = ida_name.get_name_ea(ida_idaapi.BADADDR, function_name)
    
    if function_address == ida_idaapi.BADADDR:
        return None

    func = ida_funcs.get_func(function_address)
    if not func:
        return None

    cfunc = ida_hexrays.decompile(func)
    if not cfunc:
        return None

    return "\n".join([ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()])

if __name__ == "__main__":
    file_path = Path(idaapi.get_input_file_path())
    folder_path = Path(file_path).parent
    folder_path.mkdir(exist_ok=True)

    for func_ea in idautils.Functions():

        func_name = idc.get_func_name(func_ea)
        
        asm_file_path = folder_path / f"{func_name}.asm"
        pseudo_file_path = folder_path / f"{func_name}.pseudo"

        write_file(get_function_asm(func_name), asm_file_path)
        write_file(get_pseudocode(func_name), pseudo_file_path)

    ida_pro.qexit(0)