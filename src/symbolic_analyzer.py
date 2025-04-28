import angr 

class SymbolicAnalyzer:
    def __init__(self, binary_loader):
        self.binary_loader = binary_loader
        self.project = binary_loader.project 
        self.symbols = binary_loader.get_symbols()  

    def identify_registers(self, result):
        print("\n[+] Identifying registers using concrete execution...")

        # Get address of describe_register
        describe_register_addr = self.symbols.get("describe_register")
        if describe_register_addr is None:
            print("Error: 'describe_register' symbol not found.")
            return
        
        char_to_reg = {
            0x61: "a",
            0x62: "b",
            0x63: "c",
            0x64: "d",
            0x73: "s",
            0x69: "i",
            0x66: "f"
        }

        edi_values = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]

        for edi in edi_values: 
            dummy_ret_addr = 0xdeadbeef  

            # Create initial state with concrete edi
            state = self.project.factory.call_state(
                describe_register_addr,
                edi,
                ret_addr=dummy_ret_addr,
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
                }
            )

            # Setup simulation manager
            simgr = self.project.factory.simgr(state)

            # Explore until we reach the dummy return address
            simgr.explore(find=dummy_ret_addr)

            # Process found state
            if not simgr.found:
                continue

            # Use the first found state
            state = simgr.found[0]
            rax = state.regs.rax
            try:
                # Read the first byte from the memory address in rax
                first_char = state.memory.load(rax, 1, endness=state.arch.memory_endness)
                char_value = state.solver.eval(first_char)
                if char_value in char_to_reg:
                    reg_name = char_to_reg[char_value]
                    print(f"Found identifier for register '{reg_name}': 0x{edi:x}")
                    result["register"][reg_name] = edi
            except angr.errors.SimMemoryError as e:
                print(f"Memory access error for rax=0x{state.solver.eval(rax, cast_to=int):x}: {e}")
                continue

        if not result["register"]:
            print("Error: No register identifiers found.")
        elif len(result["register"]) < len(char_to_reg):
            print(f"Warning: Only found {len(result["register"])} of {len(char_to_reg)} registers.")

    def identify_instructions(self, result):
        print("\n[+] Identifying instructions using concrete execution...")

        # Get address of describe_instruction
        describe_instruction_addr = self.symbols.get("describe_instruction")
        if describe_instruction_addr is None:
            print("Error: 'describe_instruction' symbol not found.")
            return

        for pos in range(3):
            # Valid instruction names
            valid_instructions = {"imm", "add", "stk", "stm", "ldm", "cmp", "jmp", "sys"}
    
            rdi_values = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]

            for rdi in rdi_values:
                # Create a dummy return address
                dummy_ret_addr = 0xdeadbeef  # Arbitrary address not in the binary

                # Create initial state with concrete rdi
                state = self.project.factory.call_state(
                    describe_instruction_addr,
                    rdi * (16 ** (2 * pos)),
                    ret_addr=dummy_ret_addr,
                    add_options={
                        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
                    }
                )

                # Setup simulation manager
                simgr = self.project.factory.simgr(state)

                # Explore until we reach the dummy return address
                simgr.explore(find=dummy_ret_addr)

                # Process found state
                if not simgr.found:
                    continue

                # Use the first found state
                state = simgr.found[0]
                rax = state.regs.rax
                rax_addr = state.solver.eval(rax, cast_to=int)
                try:
                    # Read bytes one at a time until null byte (up to 4 bytes)
                    str_bytes = bytearray()
                    for i in range(4):  # Max 4 bytes  
                        byte = state.memory.load(rax + i, 1, endness=state.arch.memory_endness)
                        byte_val = state.solver.eval(byte)
                        if byte_val == 0:
                            break
                        str_bytes.append(byte_val)
                    if not str_bytes:
                        continue
                    # Decode to ASCII
                    instr_name = str_bytes.decode('ascii', errors='ignore')
                    if instr_name in valid_instructions:
                        print(f"Found identifier for instruction '{instr_name}': 0x{rdi:x}")
                        result["instruction"][instr_name] = rdi
                except (angr.errors.SimMemoryError, UnicodeDecodeError) as e:
                    print(f"Error reading string at rax=0x{rax_addr:x}: {e}")
                    continue
            if result["instruction"]:
                result["opcode-order"]["ins"] = pos
                break
        if not result["instruction"]:
            print("Error: No instruction identifiers found.")
        elif len(result["instruction"]) < len(valid_instructions):
            print(f"Warning: Only found {len(result["instruction"])} of {len(valid_instructions)} instructions.")


    def run_analysis(self):
        """
        Perform symbolic analysis on the loaded binary.
        """
        result = {
            "register": {},
            "instruction": {},
            "syscall": {},
            "flag": {},
            "opcode-order": {}
        }
        self.identify_registers(result)
        self.identify_instructions(result)
        print(result['register'])
        print(result['instruction'])
        print(result['opcode-order'])