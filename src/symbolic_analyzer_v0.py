import angr
import claripy
from src.symbolic_analyzer_base import SymbolicAnalyzer

class SymbolicAnalyzerV0(SymbolicAnalyzer):
    def __init__(self, binary_loader):
        super().__init__(binary_loader)

    def identify_registers(self, result):
        print("\n[+] Identifying registers ...")

        # Get address of describe_register
        describe_register_addr = self.symbols.get("describe_register")
        assert(describe_register_addr)

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
        print("\n[+] Identifying instructions ...")

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

    def identify_syscalls(self, result):
        print("\n[+] Identifying syscalls ...")

        interpret_sys_addr = self.symbols.get("interpret_sys")
        assert(interpret_sys_addr)

        # Get puts PLT address
        puts_addr = self.project.loader.main_object.plt.get("puts")
        if puts_addr is None:
            print("Error: 'puts' PLT address not found.")
            return
     
        # Generate CFG for interpret_sys
        try:
            cfg = self.project.analyses.CFGEmulated(
                fail_fast=True,
                starts=[interpret_sys_addr],
                max_steps=1000,
                keep_state=True
            )
        except Exception as e:
            print(f"Error generating CFG for interpret_sys: {e}")
            return

        interpret_sys_func = cfg.functions.get(interpret_sys_addr)
        if not interpret_sys_func:
            print("Error: Could not analyze interpret_sys function.")
            return

        
        # Find puts calls
        syscall_str_map = {
            "[s] ... open": "open",
            "[s] ... read_code": "read_code",
            "[s] ... read_memory": "read_memory",
            "[s] ... write": "write",
            "[s] ... sleep": "sleep",
            "[s] ... exit": "exit"
        }

        puts_calls = []
        for block in interpret_sys_func.blocks:
            try:
                if block.vex.jumpkind == 'Ijk_Call' and block.vex.next.tag == 'Iex_Const':
                    if block.vex.next.con.value == puts_addr:
                        # Simulate to get rdi
                        state = self.project.factory.blank_state(addr=block.addr)
                        state.regs.rip = block.addr
                        simgr = self.project.factory.simgr(state)
                        simgr.step()
                        if simgr.active:
                            state = simgr.active[0]
                            try:
                                rdi_addr = state.solver.eval(state.regs.rdi)
                                str_bytes = bytearray()
                                for i in range(20):
                                    byte = state.memory.load(rdi_addr + i, 1, endness=state.arch.memory_endness)
                                    byte_val = state.solver.eval(byte)
                                    if byte_val == 0:
                                        break
                                    str_bytes.append(byte_val)
                                if str_bytes:
                                    sys_str = str_bytes.decode('ascii', errors='ignore')
                                    if any(key in sys_str for key in syscall_str_map):
                                        syscall_name = next((v for k, v in syscall_str_map.items() if k in sys_str), None)
                                        if syscall_name:
                                            puts_calls.append({
                                                "addr": block.addr,
                                                "string": sys_str,
                                                "syscall": syscall_name
                                            })
                            except (angr.errors.SimMemoryError, UnicodeDecodeError) as e:
                                print(f"Error reading string at rdi=0x{rdi_addr:x} for puts at 0x{block.addr:x}: {e}")
            except Exception as e:
                print(f"Error analyzing block at 0x{block.addr:x}: {e}")

        if not puts_calls:
            print("Error: No puts calls found in interpret_sys.")
            return
        
        # Test possible values
        possible_values = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]
        puts_addrs = [call["addr"] for call in puts_calls]

        for pos in range(3): 
            result["syscall"].clear()

            for val in possible_values:
                rsi_val = val * (16 ** (2 * pos))
                state = self.project.factory.call_state(
                    interpret_sys_addr,
                    0x2000000,
                    claripy.BVV(rsi_val, 32),
                    add_options={
                        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                        angr.options.SIMPLIFY_MEMORY_READS
                    }
                )

                # Initialize rdi memory
                state.memory.store(0x2000000, 0x0, size=1030)

                simgr = self.project.factory.simgr(state)
                simgr.explore(find=lambda s: s.addr in puts_addrs)

                if simgr.found:
                    for state in simgr.found:
                        for call in puts_calls:
                            if state.addr == call["addr"]:
                                print(f"Found identifier for syscall '{call['syscall']}': {hex(val)}")
                                result["syscall"][call["syscall"]] = val
                                break

            if result["syscall"]:
                result["opcode-order"]["arg1"] = pos
                break

        if not result["syscall"]:
            print("Error: No syscall identifiers found.")
        elif len(result["syscall"]) < len(syscall_str_map):
            print(f"Warning: Only found {len(result['syscall'])} of {len(syscall_str_map)} syscalls.")

    def identify_flags(self, result):
        print("\n[+] Identifying flags ...")
        describe_flags_addr = self.symbols.get("describe_flags")
        assert(describe_flags_addr)
        edi_values = [0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]
        
        for edi in edi_values:
            # Create a dummy return address
            dummy_ret_addr = 0xdeadbeef
            # Create initial state with edi set to the test value
            state = self.project.factory.call_state(
                describe_flags_addr,
                claripy.BVV(edi, 32),  # edi (32-bit, treated as byte in function)
                ret_addr=dummy_ret_addr,
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
                }
            )

            simgr = self.project.factory.simgr(state)
            simgr.explore(find=dummy_ret_addr)

            if simgr.found:
                state = simgr.found[0]
                rax = state.regs.rax
                rax_addr = state.solver.eval(rax, cast_to=int)
                try:
                    str_bytes = bytearray()
                    byte = state.memory.load(rax_addr, 1, endness=state.arch.memory_endness)
                    byte_val = state.solver.eval(byte)
                    if byte_val:
                        str_bytes.append(byte_val)
                    if str_bytes:
                        flag_string = str_bytes.decode('ascii', errors='ignore')
                        print(f"Found identifier for flag '{flag_string}': 0x{edi:x}")
                        result["flag"][flag_string] = edi
                except (angr.errors.SimMemoryError, UnicodeDecodeError) as e:
                    print(f"Error reading flag string at rax=0x{rax_addr:x} for edi=0x{edi:x}: {e}")
            else:
                print(f"No state found for edi=0x{edi:x}")
    
            
    def run_analysis(self):
        """
        Perform symbolic analysis on the loaded binary.
        """
        result = {
            "opcode-order": {},
            "instruction": {},
            "register": {},
            "flag": {},
            "syscall": {},
        }
        self.identify_registers(result)
        self.identify_instructions(result)
        self.identify_syscalls(result)
        self.identify_flags(result)
        result["opcode-order"]["arg2"] = 3 - result["opcode-order"]["arg1"] - result["opcode-order"]["ins"]
        self.save_result(result)
