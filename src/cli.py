import argparse
import os
from .binary_loader import BinaryLoader 
from .symbolic_analyzer_v0 import SymbolicAnalyzerV0
from .symbolic_analyzer_v1 import SymbolicAnalyzerV1

def create_analyzer(binary_loader):
    if binary_loader.is_v0:
        return SymbolicAnalyzerV0(binary_loader)
    else:
        return SymbolicAnalyzerV1(binary_loader)
    

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="YAN85 Symbolic Execution Toolkit")
    parser.add_argument("-b", "--binary", help="Path to the YAN85 binary file")
    parser.add_argument("-s", "--shellcode", help="Path to readable shellcode file")
    parser.add_argument("-i", "--identifiers", help="Path to pre-saved result file (YAML) for generation mode")
    return parser.parse_args()

def main():
    """Main CLI function."""
    args = parse_args()
    
    try:
        # Validate argument combinations
        if args.binary and not args.shellcode and not args.identifiers:
            # Analysis Mode: -b only
            print(f"Running in Analysis Mode:")
            print(f"  Binary: {args.binary}")
            loader = BinaryLoader(args.binary)
            
            # Call symbolic_analyzer to analyze binary
            loader = BinaryLoader(args.binary)

            analyzer = create_analyzer(loader)
            analyzer.run_analysis()
        elif args.shellcode and args.identifiers and not args.binary:
            # Generation Mode: -s and -i
            if not os.path.isfile(args.shellcode):
                raise ValueError(f"Shellcode file not found: {args.shellcode}")
            if not os.path.isfile(args.identifiers):
                raise ValueError(f"Identifiers file not found: {args.identifiers}")
            print(f"Running in Generation Mode:")
            print(f"  Shellcode: {args.shellcode}")
            print(f"  Identifiers File: {args.identifiers}")
            # TODO: Call shellcode_generator with args.identifiers and args.shellcode
        elif args.binary and args.shellcode and not args.identifiers:
            # Analysis + Generation Mode: -b and -s
            if not os.path.isfile(args.shellcode):
                raise ValueError(f"Shellcode file not found: {args.shellcode}")
            print(f"Running in Analysis + Generation Mode:")
            print(f"  Binary: {args.binary}")
            print(f"  Shellcode: {args.shellcode}")
            loader = BinaryLoader(args.binary)
            loader.print_symbols()
            # TODO: Call symbolic_analyzer and shellcode_generator
        else:
            # Invalid combinations (e.g., -i without -s, no arguments, etc.)
            raise ValueError("Invalid arguments. Use:\n"
                           "  Analysis Mode: -b\n"
                           "  Generation Mode: -s and -i\n"
                           "  Analysis + Generation Mode: -b and -s")
    
    except ValueError as e:
        print(f"Error: {e}")
        exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        exit(1)

if __name__ == "__main__":
    main()