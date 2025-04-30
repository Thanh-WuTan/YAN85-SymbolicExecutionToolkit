# YAN85-SymbolicExecutionToolkit

**YAN85-SymbolicExecutionToolkit** is a Python-based tool designed specifically for symbolic execution and shellcode generation in **YAN85-based challenges on [pwn.college](https://pwn.college)**.

This toolkit automates the analysis of YAN85 binaries by identifying instructions, registers, and syscalls through symbolic execution. It also enables users to convert human-readable shellcode into YAN85 shellcode using previously extracted identifiers, making the reverse engineering process more efficient.

> **Disclaimer**: Reversing YAN85 binaries is a practice space for improving reverse engineering skills. Use this tool only if you find manually identifying YAN85 opcodes tedious.

## Setup

### Clone the repository:
```bash
git clone https://github.com/yourusername/YAN85-SymbolicExecutionToolkit.git
cd YAN85-SymbolicExecutionToolkit
```

### Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage
Run the toolkit using the main CLI script:
```bash
python main.py -h
```
###  Command-Line Options
```plain
usage: cli.py [-h] [-b BINARY] [-s SHELLCODE] [-i IDENTIFIERS]

YAN85 Symbolic Execution Toolkit

options:
  -h, --help            show this help message and exit
  -b BINARY, --binary BINARY
                        Path to the YAN85 binary file
  -s SHELLCODE, --shellcode SHELLCODE
                        Path to readable shellcode file
  -i IDENTIFIERS, --identifiers IDENTIFIERS
                        Path to pre-saved result file (YAML) for generation mode
```

## Example
### Analysis Mode
Analyze a YAN85 binary to extract identifiers and save results to a YAML file:

```bash
python main.py -b path/to/yan85_binary
```

Output: Saves extracted identifiers to `./result/identifiers/<binary_name>.yml`

### Generation Mode
Generate YAN85 shellcode from a readable shellcode file using a pre-saved YAML result:
```bash
python main.py -s path/to/readable_shellcode -i path/to/saved_identifiers.yml
```

- See `example_readable_shellcode` for a sample shellcode file.
- See `example_saved_identifiers.yml` for a sample identifiers YAML file.

Output: Saves YAN85 shellcode to `.result/shellcode/generated_shellcode`

### Analysis + Generation Mode

```bash
python main.py -b path/to/yan85_binary -s path/to/readable_shellcode
```

Output: 
- Saves extracted identifiers to `./result/identifiers/<binary_name>.yml`
- Saves YAN85 shellcode to `.result/shellcode/<binary_name>_shellcode`
