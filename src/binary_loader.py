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
        self.potential_functions = None
        if self.is_v0 == False:
            self._construct_dict_symbols()
            

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
            self.symbols = {}
            return False
        else:
            return True
    
    def _construct_dict_symbols(self):
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
        self.potential_functions = []
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
                                    self.potential_functions.append((func_start, func_end))
                                    i = j + ins_end.size
                                    break
                                elif ins_end.mnemonic == "endbr64":
                                    func_end = ins_end.address
                                    self.potential_functions.append((func_start, func_end))
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
        
        # Store functions with generic names
        for idx, (start, end) in enumerate(self.potential_functions):
            if start not in self.symbols.values():
                self.symbols[f"sub_{start:x}"] = start

        if not self.symbols:
            raise("Error: No functions identified.")

        try:
            # Check PLT section
            plt_section = None
            for section in self.project.loader.main_object.sections:
                if section.name in ['.plt', '.plt.got']:
                    plt_section = section
                    break
            if plt_section: 
                for addr, name in self.project.loader.main_object.plt.items():
                    self.symbols[addr] = name
            else:
                print("Warning: No .plt section found.")
        except Exception as e:
            print(f"Error analyzing PLT symbols: {e}")
        
        