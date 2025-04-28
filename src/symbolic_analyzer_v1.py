import claripy
import angr

class SymbolicAnalyzerV1:
    def __init__(self, binary_loader):
        self.binary_loader = binary_loader
        self.symbols = binary_loader.symbols
        self.project = binary_loader.project

    def _get_interpret_funcs(self):
        # Heuristic to find interpret_instruction function
        target_size = 0xff
        closest_size_diff = float('inf')
        interpret_instruction_addr = None
        for start, end in self.binary_loader.potential_functions:
            size = end - start
            size_diff = abs(size - target_size)
            if size_diff < closest_size_diff:
                closest_size_diff = size_diff
                interpret_instruction_addr = start

        if not interpret_instruction_addr:
            raise ValueError("Cannot find interpret_instruction function.")
        self.symbols['interpret_instruction'] = self.symbols.pop(f'sub_{interpret_instruction_addr:x}')

        interpret_funcs = set()
        for start, end in self.binary_loader.potential_functions:
            if start == interpret_instruction_addr:
                try:
                    func_data = self.project.loader.memory.load(start, end - start)
                    for ins in self.binary_loader.md.disasm(func_data, start):
                        if ins.mnemonic == "call":
                            try:
                                call_addr = int(ins.op_str, 16)
                                # Check if call target is a known function
                                for func_start, _ in self.binary_loader.potential_functions:
                                    if func_start == call_addr:
                                        # Find the symbol name for this address
                                        for name, addr in self.symbols.items():
                                            if addr == call_addr:
                                                interpret_funcs.add((name, call_addr))
                                                break
                            except ValueError:
                                continue  # Skip non-numeric call targets (e.g., registers)
                except Exception as e:
                    print(f"Error analyzing interpret_instruction at 0x{start:x}: {e}")
                break

        return interpret_funcs

    def identify_instructions(self, result, interpret_funcs):
        interpret_instruction_addr = self.symbols.get("interpret_instruction")
        if not interpret_instruction_addr:
            print("Error: interpret_instruction symbol not found.")
            return


        tmp_result_instruction = {}
        # List of rsi values to test
        rsi_values = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]

        # Dictionary to map function addresses to names for quick lookup
        func_addr_to_name = {addr: name for name, addr in interpret_funcs}
        for pos in range(3):
            for rsi_val in rsi_values:
                # Create a dummy return address
                dummy_ret_addr = 0xdeadbeef  # Arbitrary address not in the binary

                # Create initial state with concrete rsi and a symbolic rdi (first argument)
                state = self.project.factory.call_state(
                    interpret_instruction_addr,
                    claripy.BVV(0, 64),  # Dummy rdi (a1, pointer to unsigned __int8)
                    claripy.BVV(rsi_val * (16 ** (2 * pos)), 64),  # Concrete rsi (a2)
                    ret_addr=dummy_ret_addr,
                    add_options={
                        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
                    }
                )

                # Setup simulation manager
                simgr = self.project.factory.simgr(state)

                # Step until we hit a call instruction or return
                def is_call_instruction(state):
                    try:
                        block = self.project.factory.block(state.addr)
                        if block.capstone.insns:
                            last_ins = block.capstone.insns[-1]
                            return last_ins.mnemonic == "call"
                    except:
                        return False
                    return False

                called_func = None
                while simgr.active and not called_func:
                    simgr.step()
                    for state in simgr.active:
                        if is_call_instruction(state):
                            # Get the call target
                            block = self.project.factory.block(state.addr)
                            if block.capstone.insns:
                                call_ins = block.capstone.insns[-1]
                                try:
                                    call_addr = int(call_ins.op_str, 16)
                                    if call_addr in func_addr_to_name:
                                        called_func = func_addr_to_name[call_addr]
                                        tmp_result_instruction[call_addr] = rsi_val
                                        break
                                except ValueError:
                                    continue
                        elif state.addr == dummy_ret_addr:
                            break
                    simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == dummy_ret_addr)

            if tmp_result_instruction:
                result["opcode-order"]["ins"] = pos
                break 
        
        def find_interpret_imm(tmp_result_instruction):
            offset_to_register = {
                1024: "a",
                1025: "b",
                1026: "c",
                1027: "d",
                1028: "s",
                1029: "i",
                1030: "f"
            }
            for interpret_func_addr, identifier in tmp_result_instruction.items():
                ins_pos = result["opcode-order"].get("ins")
                rem_pos = {0, 1, 2} - {ins_pos}
                arg2 = 0xcc
                for arg1_pos in rem_pos:
                    arg2_pos = 3 - arg1_pos - ins_pos
                    for arg1 in [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]:
                        rsi_bytes = [0] * 3  # three positions: 0, 1, 2
                        rsi_bytes[ins_pos] = identifier
                        rsi_bytes[arg1_pos] = arg1
                        rsi_bytes[arg2_pos] = arg2

                        # Now pack them into a 32-bit integer (little endian)
                        rsi_val = rsi_bytes[0] | (rsi_bytes[1] << 8) | (rsi_bytes[2] << 16)

                        dummy_ret_addr = 0xdeadbeef  # Arbitrary address not in the binary
                        state = self.project.factory.call_state(
                            interpret_func_addr,
                            0x2000000,
                            claripy.BVV(rsi_val, 32),
                            ret_addr=dummy_ret_addr,
                            add_options={
                                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
                            }
                        )
                        state.memory.store(0x2000000, 0x0, size=1030)
                        simgr = self.project.factory.simgr(state)
                        simgr.explore(find=dummy_ret_addr)
                        
                        if simgr.found:
                            found_state = simgr.found[0]
                            base_addr = 0x2000000

                            # Now check a1[1024] to a1[1030]
                            for offset in range(1024, 1031):
                                mem_byte = found_state.memory.load(base_addr + offset, 1)
                                mem_byte_val = found_state.solver.eval(mem_byte)
                                
                                if mem_byte_val == 0xcc:
                                    reg_name = offset_to_register[offset]
                                    result["opcode-order"]["arg1"] = arg1_pos
                                    result["opcode-order"]["arg2"] = arg2_pos
                                    result["instruction"]["imm"] = identifier
                                    result["register"][reg_name] = arg1
                                    
                if result["instruction"].get("imm") is not None:
                    break   
             
        
        find_interpret_imm(tmp_result_instruction)

    def run_analysis(self):
        """
        Run the full analysis and return results.
        """
        result = {
            "register": {},
            "instruction": {},
            "syscall": {},
            "flag": {},
            "opcode-order": {}
        }
        
        interpret_funcs = self._get_interpret_funcs()
     
        
        
        self.identify_instructions(result, interpret_funcs)
        print(result["register"])
        print(result["instruction"])
        print(result["opcode-order"])
