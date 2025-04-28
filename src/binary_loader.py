import angr
import logging

# Suppress Angr's verbose logging
logging.getLogger('angr').setLevel(logging.ERROR)

class BinaryLoader:
    # Define required YAN85 symbols
    REQUIRED_SYMBOLS = {
        "describe_register",
        "describe_instruction",
        "describe_flags",
        "interpret_sys"
    }

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.project = None
        self.symbols = None
        self._load_binary()
        self._check_required_symbols()

    def _load_binary(self):
        """Load the binary into an Angr project."""
        try:
            self.project = angr.Project(self.binary_path, auto_load_libs=False)
        except Exception as e:
            raise ValueError(f"Error loading binary: {e}")

    def _check_required_symbols(self):
        """Verify that all required YAN85 symbols are present."""
        if not self.project:
            raise ValueError("Binary not loaded.")
        
        # Get all symbols from the main binary
        self.symbols = {symbol.name: symbol.rebased_addr for symbol in self.project.loader.main_object.symbols if symbol.name}
        
        # Check for missing symbols
        missing_symbols = self.REQUIRED_SYMBOLS - set(self.symbols.keys())
        if missing_symbols:
            raise ValueError("make sure the input binary is yan85 level .0")

    def get_symbols(self):
        """Return required symbols with their addresses."""
        if not self.symbols:
            raise ValueError("Symbols not loaded.")
        
        # Return only required symbols
        return [(name, addr) for name, addr in self.symbols.items() if name in self.REQUIRED_SYMBOLS]

    def print_symbols(self):
        """Print required symbols and their addresses in a formatted table."""
        symbols = self.get_symbols()
        
        print(f"\nRequired Symbols in {self.binary_path}:")
        print("Symbol Name".ljust(40) + "Address")
        print("-" * 60)
        
        if not symbols:
            print("No required symbols found.")
        else:
            for name, addr in sorted(symbols):  # Sort for consistent output
                print(f"{name.ljust(40)} 0x{addr:08x}")