import angr
import logging
import os
from capstone import *

# Suppress Angr's verbose logging
logging.getLogger('angr').setLevel(logging.ERROR)

class BinaryLoader:
    # Define required YAN85 symbols
    REQUIRED_SYMBOLS_V0 = {
        "describe_register",
        "describe_instruction",
        "describe_flags",
        "interpret_sys"
    }

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(self.binary_path)
        self.project = None
        self.symbols = {}   
        self._load_binary()
        self.is_v0 = self._check_required_symbols()
        
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        if self.is_v0 == False:
            self._recover_symbols()

    def _load_binary(self):
        """Load the binary into an Angr project."""
        try:
            self.project = angr.Project(self.binary_path, auto_load_libs=False)
        except Exception as e:
            raise ValueError(f"Error loading binary: {e}")

    def _check_required_symbols(self):
        """Verify that all required YAN85 symbols are present and store them."""
        if not self.project:
            raise ValueError("Binary not loaded.")
        
        # Get all symbols from the main binary
        all_symbols = {symbol.name: symbol.rebased_addr for symbol in self.project.loader.main_object.symbols if symbol.name}
        
        # Keep only required symbols
        self.symbols = {name: addr for name, addr in all_symbols.items() if name in self.REQUIRED_SYMBOLS_V0}
        
        # Check for missing required symbols
        missing_symbols = self.REQUIRED_SYMBOLS_V0 - self.symbols.keys()
        if missing_symbols:
            print("Given binary is v1")
            return False
        else:
            print("Given binary is v0")
            return True
    
    def _recover_symbols(self):
        """
        Recover symbols by scanning assembly for functions starting with endbr64 and ending with ret/leave/hlt.
        Ensure each function has exactly one endbr64. Assign 'interpret_instruction' to function with size nearest to 0xff.
        """
        print("\n[+] Recovering symbols by scanning assembly...")

        # Get binary code section
        text_section = None
        for section in self.project.loader.main_object.sections:
            if section.name == '.text':
                text_section = section
                break
        
        if not text_section:
            print("Error: .text section not found.")
            return

        text_addr = text_section.vaddr
        text_size = text_section.memsize
        text_data = self.project.loader.memory.load(text_addr, text_size)

        # Scan for functions
        potential_functions = []
        i = 0
        while i < text_size:
            try:
                # Disassemble from current offset
                for ins in self.md.disasm(text_data[i:i+16], text_addr + i):
                    if ins.mnemonic == "endbr64":
                        func_start = ins.address
                        func_end = None
                        j = i + ins.size
                        # Look for ret, leave, hlt, or next endbr64 to mark function end
                        while j < text_size:
                            for ins_end in self.md.disasm(text_data[j:j+16], text_addr + j):
                                if ins_end.mnemonic in ["ret", "leave", "hlt"]:
                                    func_end = ins_end.address + ins_end.size
                                    potential_functions.append((func_start, func_end))
                                    i = j + ins_end.size
                                    break
                                elif ins_end.mnemonic == "endbr64":
                                    func_end = ins_end.address
                                    potential_functions.append((func_start, func_end))
                                    i = j
                                    break
                                j += ins_end.size
                            if func_end:
                                break
                            if j >= text_size:
                                i = j
                                break
                        if not func_end:
                            i = j
                    else:
                        i += ins.size
                    break
            except Exception as e:
                print(f"Error disassembling at 0x{text_addr + i:x}: {e}")
                i += 1
        
        # Store functions with generic names, assign interpret_instruction
        for idx, (start, end) in enumerate(potential_functions):
            if start not in self.symbols.values():
                self.symbols[f"sub_{start:x}"] = start

        # Find function with size closest to 0xff
        target_size = 0xff
        closest_size_diff = float('inf')
        interpret_instruction_addr = None
        for start, end in potential_functions:
            size = end - start
            size_diff = abs(size - target_size)
            if size_diff < closest_size_diff:
                closest_size_diff = size_diff
                interpret_instruction_addr = start

        if not interpret_instruction_addr:
            raise ValueError("Cannot find interpret_instruction function.")
        self.symbols['interpret_instruction'] = self.symbols.pop(f'sub_{interpret_instruction_addr:x}')



        if not self.symbols:
            print("Error: No functions identified.")
            return

        print(f"\n[+] Recovered symbols:")
        for name, addr in self.symbols.items():
            print(f"  {name}: 0x{addr:x}")

    def get_symbols(self):
        """Return the dictionary of required symbols and their addresses."""
        if not self.symbols:
            raise ValueError("Symbols not loaded.")
        return self.symbols

    def print_symbols(self):
        """Print required symbols and their addresses in a formatted table."""
        if not self.symbols:
            print("No required symbols found.")
            return
        
        print(f"\nRequired Symbols in {self.binary_path}:")
        print("Symbol Name".ljust(40) + "Address")
        print("-" * 60)
        
        for name in sorted(self.symbols.keys()):  # Sort for consistent output
            addr = self.symbols[name]
            print(f"{name.ljust(40)} 0x{addr:08x}")
