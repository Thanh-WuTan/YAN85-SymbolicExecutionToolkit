import argparse
from .binary_loader import BinaryLoader

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="YAN85 Symbolic Execution Toolkit")
    parser.add_argument("-b", "--binary", required=True, help="Path to the YAN85 binary file")
    # Add -g and -o flags later for shellcode and output file
    return parser.parse_args()

def main():
    args = parse_args()
    
    try:
        # Load binary and print symbols
        loader = BinaryLoader(args.binary)
        loader.print_symbols()
    except ValueError as e:
        print(e)
        exit(1)

if __name__ == "__main__":
    main()