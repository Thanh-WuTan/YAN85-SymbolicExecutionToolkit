import yaml
import os
from pwn import p8


class ShellcodeGenerator:
    def __init__(self, shellcode_path, identifiers_path, binary_name):
        self.shellcode_path = shellcode_path
        self.identifiers_path = identifiers_path
        self.binary_name = binary_name + "_shellcode" if binary_name else "generated_shellcode"
        self.shellcode = None
        self.identifiers = None

        # Validate and load inputs
        self._validate_identifiers_file()
        self._load_identifiers()
        self._validate_shellcode_file()
        self._load_shellcode()

    def _validate_identifiers_file(self):
        if not os.path.isfile(self.identifiers_path):
            raise ValueError(f"Identifiers file not found: {self.identifiers_path}")
        if not self.identifiers_path.lower().endswith(".yml") and not self.identifiers_path.lower().endswith(".yaml"):
            raise ValueError(f"Identifiers file must be a YAML file (.yml or .yaml): {self.identifiers_path}")
        try:
            with open(self.identifiers_path, "r", encoding="utf-8") as f:
                yaml.safe_load(f)  # Test if it's valid YAML
        except (IOError, yaml.YAMLError) as e:
            raise ValueError(f"Identifiers file is not readable or not valid YAML: {e}")

    def _load_identifiers(self): 
        try:
            print("\n[+] Loading identifiers...")
            with open(self.identifiers_path, "r", encoding="utf-8") as f:
                self.identifiers = yaml.safe_load(f)
            if not self.identifiers:
                raise ValueError("Identifiers YAML file is empty")

            required_sections = {
                "opcode-order": ["ins", "arg1", "arg2"],
                "register": ["a", "b", "c", "d", "s", "i", "f"],
                "instruction": ["imm", "add", "stk", "stm", "ldm", "cmp", "jmp", "sys"],
                "flag": ["L", "N", "G", "E", "Z", "*"],
                "syscall": ["read_code", "read_memory", "write", "open", "exit", "sleep"]
            }
            
            for section in required_sections:
                if section == "syscall": 
                    continue
                if section not in self.identifiers:
                    raise ValueError(f"Identifiers YAML missing required section: {section}")

            # Helper function to validate power-of-2 and uniqueness
            def validate_power_of_2(values, section_name, max_power, allow_zero=False):
                valid_powers = [2**x for x in range(max_power + 1)]
                if allow_zero:
                    valid_powers.append(0)
                if not all(isinstance(v, int) for v in values):
                    raise ValueError(f"{section_name} values must be integers")
                invalid_values = [v for v in values if v not in valid_powers]
                if invalid_values:
                    raise ValueError(f"{section_name} values must be powers of 2 (max_power = {max_power}): invalid values {invalid_values}")
                if len(set(values)) != len(values):
                    raise ValueError(f"{section_name} values must be unique")

            for section in required_sections:
                max_power = 1 if section == "opcode-order" else 7
                allow_zeror = True if section == "opcode-order" else False
                for key in self.identifiers[section]:
                    if key not in required_sections[section]:
                        raise ValueError(f"Invalid key '{key}' in section '{section}'")
                if section == 'flag' and '*' in self.identifiers[section] and self.identifiers[section]['*'] != 0:
                    raise ValueError(f"Invalid value for '*' in section '{section}': must be 0")
                values = [self.identifiers[section][key] for key in self.identifiers[section] if key != '*']
                validate_power_of_2(values, section, max_power, allow_zero=allow_zeror)
                
            print(f"[+] Loaded and validated identifiers from {self.identifiers_path}")

        except (IOError, yaml.YAMLError) as e:
            raise ValueError(f"Failed to load or parse identifiers YAML: {e}")

    def _validate_shellcode_file(self):
        if not os.path.isfile(self.shellcode_path):
            raise ValueError(f"Shellcode file not found: {self.shellcode_path}")
        try:
            with open(self.shellcode_path, "r", encoding="utf-8") as f:
                f.read(1024)  # Try reading a small portion to check if it's text
        except (IOError, UnicodeDecodeError) as e:
            raise ValueError(f"Shellcode file is not readable or not a text file: {e}")

    def _load_shellcode(self):
        try:
            print("\n[+] Loading shellcode...")
            with open(self.shellcode_path, "r", encoding="utf-8") as f:
                self.shellcode = f.read()
            for line in self.shellcode.splitlines():
                opcodes = line.split()
                if len(opcodes) != 3:
                    raise ValueError(f"Invalid shellcode: {line}. Expected format: 'ins arg1 arg2'")
                if opcodes[0] not in self.identifiers["instruction"]:
                    raise ValueError(f"Invalid instruction '{opcodes[0]}' in shellcode. Must be one of {list(self.identifiers['instruction'].keys())}")
                if opcodes[0] == "imm":
                    if opcodes[1] not in self.identifiers["register"]:
                        raise ValueError(f"Invalid register '{opcodes[1]}' in shellcode. Must be one of {list(self.identifiers['register'].keys())}")
                    if not opcodes[2].isdigit():
                        raise ValueError(f"Invalid immediate value '{opcodes[2]}' in shellcode. Must be a number")
                elif opcodes[0] == "sys":
                    if opcodes[1] not in self.identifiers["syscall"]:
                        raise ValueError(f"Invalid syscall '{opcodes[1]}' in shellcode. Must be one of {list(self.identifiers['syscall'].keys())}")
                elif opcodes[0] == "jmp":
                    for flag in opcodes[1]:
                        if flag not in self.identifiers["flag"]:
                            raise ValueError(f"Invalid flag '{flag}' in shellcode. Must be one of {list(self.identifiers['flag'].keys())}")
                elif opcodes[0] == "stk":
                    for arg in range(1, 3):
                        if opcodes[arg] != "0" and opcodes[arg] not in self.identifiers["register"]:
                            raise ValueError(f"Invalid register '{opcodes[arg]}' in shellcode. Must be one of {list(self.identifiers['register'].keys())}")
                else:
                    for arg in range(1, 3):
                        if opcodes[arg] not in self.identifiers["register"]:
                            raise ValueError(f"Invalid register '{opcodes[arg]}' in shellcode. Must be one of {list(self.identifiers['register'].keys())}")
            print(f"[+] Loaded and validated shellcode from {self.shellcode_path}")
        except IOError as e:
            raise ValueError(f"Failed to read shellcode file: {e}")

    def save_shellcode(self, shellcode):
        import os
        import yaml

        print("\n[+] Saving result to YAML file...")
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(base_dir, "result", "shellcode")
        os.makedirs(output_dir, exist_ok=True) 
        output_file = os.path.join(output_dir, f"{self.binary_name}")
        try:
            with open(output_file, "wb") as f:
                f.write(shellcode)
            print(f"[+] Shellcode saved to {output_file}")
        except Exception as e:
            print(f"[!] Error writing shellcode to {output_file}: {e}")

    def generate_shellcode(self):
        print("\n[+] Generating shellcode...")
        shellcode = b''
        ins_pos = self.identifiers["opcode-order"]["ins"]
        arg1_pos = self.identifiers["opcode-order"]["arg1"]
        arg2_pos = self.identifiers["opcode-order"]["arg2"]
        for line in self.shellcode.splitlines():
            ins, arg1, arg2 = line.split()
            sc = [0] * 3
            if ins == "imm":
                sc[ins_pos] = self.identifiers["instruction"][ins]
                sc[arg1_pos] = self.identifiers["register"][arg1]
                sc[arg2_pos] = int(arg2)
            elif ins == "sys":
                sc[ins_pos] = self.identifiers["instruction"][ins]
                sc[arg1_pos] = self.identifiers["syscall"][arg1]
                sc[arg2_pos] = self.identifiers["register"][arg2]
            elif ins == "jmp":
                sc[ins_pos] = self.identifiers["instruction"][ins]
                sc[arg1_pos] = 0
                sc[arg2_pos] = self.identifiers["register"][arg2]
                for flag in arg1:
                    sc[ins_pos] |= self.identifiers["flag"][flag]
            else:
                sc[ins_pos] = self.identifiers["instruction"][ins]
                sc[arg1_pos] = self.identifiers["register"][arg1] if arg1 != "0" else 0
                sc[arg2_pos] = self.identifiers["register"][arg2] if arg2 != "0" else 0
            shellcode += b''.join([p8(x) for x in sc])
        print(f"[+] Generated shellcode with length {len(shellcode)} bytes")
        self.save_shellcode(shellcode)

 