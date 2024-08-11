import ida_idaapi
import ida_kernwin
import ida_lines
import ida_funcs
import ida_hexrays
import ida_bytes
import ida_ua
import ida_name
import idautils
import idc
import idaapi  # Add this import
import os
import re


# Decompile view
class LLMDecompilerView(ida_kernwin.simplecustviewer_t):
    def Create(self, title):
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False
        # Add "Decompile pseudocode" to the viewer
        self.AddLine("Decompile pseudocode")
        return True

    # close  viewer
    def OnKeydown(self, vkey, shift):
        if vkey == ord('X'):
            self.Close()
        return True


# Plugin
class CodeLlamaDecompilerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Show decompile pseudocode and export function"
    help = "This plugin shows Decompile in a custom viewer and exports the current function"
    wanted_name = "LLM Decompile"  # Plugin name
    wanted_hotkey = "Ctrl-Shift-K"  # Plugin hotkey

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        # plugin run
        # Create and display Decompile view
        viewer = LLMDecompilerView()
        if viewer.Create("Decompile Viewer"):
            viewer.Show()
        else:
            print("Failed to create Decompile viewer")

        # Get the address of the current mouse position
        current_ea = ida_kernwin.get_screen_ea()
        # Get the function where the address is located
        func = ida_funcs.get_func(current_ea)
        if func:
            # If a function is found, export the function and use the API to get function information
            self.export_function(func)

            # Use the new API interface to obtain function information
            func_info = self.api_get_function_info(current_ea)
            if func_info:
                print(f"Function Name: {func_info['name']}")
                print("Assembly (first 5 lines):")
                print("\n".join(func_info['assembly'].split("\n")[:5]))
                print("\nPseudocode (first 5 lines):")
                print("\n".join(func_info['pseudocode'].split("\n")[:5]))
        else:
            print("No function found at current address.")

    def term(self):
        # How to handle plugin termination
        pass

    def export_function(self, func):
        # Export the assembly and pseudocode of the function to the desktop
        func_name = ida_funcs.get_func_name(func.start_ea)
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")

        # Export assembly
        asm_path = os.path.join(desktop_path, f"{func_name}_assembly.txt")
        with open(asm_path, "w") as f:
            f.write(self.get_assembly(func_name))
        print(f"Assembly exported to {asm_path}")

        # Export pseudocode
        pseudo_path = os.path.join(desktop_path, f"{func_name}_pseudocode.txt")
        with open(pseudo_path, "w") as f:
            f.write(self.get_pseudocode(func_name))
        print(f"Pseudocode exported to {pseudo_path}")

    def get_assembly(self, func_name):
        # Read the function's assembly
        func_addr = idc.get_name_ea_simple(func_name)
        if func_addr == idc.BADADDR:
            return "Function not found"
        func = idaapi.get_func(func_addr)
        if not func:
            return "Function not found"
        func_start, func_end = func.start_ea, func.end_ea
        asm_code = [f"{func_name} proc near\n"]
        for head in idautils.Heads(func_start, func_end):
            disasm_line = idc.generate_disasm_line(head, 0)
            if disasm_line:
                asm_code.append(disasm_line)
        return '\n'.join(asm_code + [f"{func_name} endp\n"])

    def get_pseudocode(self, function_name):
        # Read the function's pseudocode
        function_address = ida_name.get_name_ea(ida_idaapi.BADADDR, function_name)
        if function_address == ida_idaapi.BADADDR:
            return "Function not found"
        func = ida_funcs.get_func(function_address)
        if not func:
            return "Function not found"
        cfunc = ida_hexrays.decompile(func)
        if not cfunc:
            return "Failed to decompile function"
        return str(cfunc)

    def api_get_function_info(self, ea):
        # API interface: Get function information of the specified address
        func = ida_funcs.get_func(ea)  # 獲取指定地址的function
        if func:
            func_name = ida_funcs.get_func_name(func.start_ea)
            return {
                "name": func_name,  # 獲取function name
                "assembly": self.get_assembly(func_name),  # 獲取assembly
                "pseudocode": self.get_pseudocode(func_name)  # 獲取pseudocode
            }
        else:
            return None


# IDAplugin entry
def PLUGIN_ENTRY():
    return CodeLlamaDecompilerPlugin()