import claripy
import angr
from src.symbolic_analyzer_base import SymbolicAnalyzer
OFFSET_TO_REG = {
        1024: "a",
        1025: "b",
        1026: "c",
        1027: "d",
        1028: "s",
        1029: "i",
        1030: "f"
    }

REG_TO_OFFSET = {
    "a": 1024,
    "b": 1025,
    "c": 1026,
    "d": 1027,
    "s": 1028,
    "i": 1029,
    "f": 1030,
}
class SymbolicAnalyzerV1(SymbolicAnalyzer):
    
    def __init__(self, binary_loader):
        super().__init__(binary_loader)

    def get_interpret_funcs(self):
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
        print(f"Heursitically found interpret_instruction at 0x{interpret_instruction_addr:x}")
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

    def symbols_recovery(self, result, interpret_funcs):
        
        interpret_instruction_addr = self.symbols.get("interpret_instruction")
        if not interpret_instruction_addr:
            print("Error: interpret_instruction symbol not found.")
            return


        tmp_result_instruction = {} 
        rsi_values = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]
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
        
    

        def construct_arg(ins_pos, arg1_pos, arg2_pos, ins, arg1, arg2):
            arg_bytes = [0] * 3
            arg_bytes[ins_pos] = ins
            arg_bytes[arg1_pos] = arg1
            arg_bytes[arg2_pos] = arg2
            return arg_bytes[0] | (arg_bytes[1] << 8) | (arg_bytes[2] << 16)

        def simulate(function, rdi, rsi, init_register, init_memory, ret_addr, target_addr):
            state = self.project.factory.call_state(
                function,
                rdi,
                rsi,
                ret_addr=ret_addr,
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
                }
            )
            state.memory.store(rdi, 0x0, size=1030)
            for reg, val in init_register.items():
                state.memory.store(rdi + REG_TO_OFFSET[reg], val, 1)
            for (offset, val) in init_memory:
                state.memory.store(rdi + offset, val, 1)
            simgr = self.project.factory.simgr(state)
            simgr.explore(find=target_addr)
            return simgr

        def get_mem_byte_val(state, base, offset):
            mem_byte = state.memory.load(base + offset, 1)
            return state.solver.eval(mem_byte)
    
        def identify_register():
            print("\n[+] Identifying registers ...")
            # Identify register by finding interpret_imm symbol 
            for interpret_imm, imm in tmp_result_instruction.items():
                ins_pos = result["opcode-order"].get("ins")
                rem_pos = {0, 1, 2} - {ins_pos}
                arg2 = 0xcc
                for arg1_pos in rem_pos:
                    arg2_pos = 3 - arg1_pos - ins_pos
                    for arg1 in [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]:
                        rsi_val = construct_arg(ins_pos, arg1_pos, arg2_pos, imm, arg1, arg2)
                        base_addr = 0x2000000
                        simgr = simulate(interpret_imm, base_addr, claripy.BVV(rsi_val, 32), {}, {}, 0xdeadbeef, 0xdeadbeef)
                        if simgr.found:
                            found_state = simgr.found[0]
                            for offset in range(1024, 1031):
                                mem_byte_val = get_mem_byte_val(found_state, base_addr, offset)
                                if mem_byte_val == 0xcc:
                                    reg_name = OFFSET_TO_REG[offset]
                                    result["opcode-order"]["arg1"] = arg1_pos
                                    result["opcode-order"]["arg2"] = arg2_pos
                                    result["instruction"]["imm"] = imm
                                    result["register"][reg_name] = arg1
                                    print(f"Found identifier for register '{reg_name}': 0x{arg1:x}")
                                    
                if result["instruction"].get("imm") is not None:
                    print("\n[+] Identifying instructions ...")
                    print(f"Found interpret_imm at 0x{interpret_imm:x}, with identifier 0x{imm:x}")
                    tmp_result_instruction.pop(interpret_imm)
                    self.binary_loader.symbols["interpret_imm"] = self.binary_loader.symbols.pop(f"sub_{interpret_imm:x}")
                    return
            
            print("\n[!] Warning: Cannot find interpret_imm")
                
        def identify_flags(ins_pos, arg1_pos, arg2_pos):
            print("\n[+] Identifying flags ...")

            if result["instruction"].get("cmp") and self.binary_loader.symbols.get("interpret_cmp"):
                cmp = result["instruction"].get("cmp")
                interpret_cmp = self.binary_loader.symbols.get("interpret_cmp")
                test_values = {
                    "L": {"a": 0, "b": 1},
                    "G": {"a": 1, "b": 0},
                    "E": {"a": 1, "b": 1},
                    "N": {"a": 1, "b": 0},
                    "Z": {"a": 0, "b": 0},
                }
                for test in test_values.items():
                    flag = test[0]
                    reg_a_val = test[1].get("a")
                    reg_b_val = test[1].get("b")
                    rsi_val = construct_arg(ins_pos, arg1_pos, arg2_pos, cmp, result["register"]["a"], result["register"]["b"])
                    init_register = {"a": reg_a_val, "b": reg_b_val}
                    base_addr = 0x2000000
                    simgr = simulate(interpret_cmp, base_addr, claripy.BVV(rsi_val, 32), init_register, {}, 0xdeadbeef, 0xdeadbeef)
                    if simgr.found:
                        found_state = simgr.found[0]
                        mem_byte_val = get_mem_byte_val(found_state, base_addr, REG_TO_OFFSET["f"])
                        result["flag"][flag] = mem_byte_val
                
                flag_N = result["flag"]["L"] & result["flag"]["G"]
                result["flag"]["N"] = flag_N
                result["flag"]["L"]^= flag_N
                result["flag"]["G"]^= flag_N
                result["flag"]["Z"]^= result["flag"]["E"]
                for flag, id in result["flag"].items():
                    print(f"Found identifier for flag '{flag}': 0x{id:x}")

            else:
                print("\n[!] Warning: Cannot identify flags")

        def identify_syscalls(ins_pos, arg1_pos, arg2_pos):
            print("\n[+] Identifying syscalls ...")

            if result["instruction"].get("sys") and self.binary_loader.symbols.get("interpret_sys"):
                sys = result["instruction"].get("sys")
                interpret_sys = self.binary_loader.symbols.get("interpret_sys")
                open_plt = self.binary_loader.symbols.get("open")
                write_plt = self.binary_loader.symbols.get("write")
                sleep_plt = self.binary_loader.symbols.get("sleep")
                exit_plt = self.binary_loader.symbols.get("exit")
                read_plt = self.binary_loader.symbols.get("read")

                # Map PLT addresses to syscall names
                plt_to_syscall = {
                    open_plt: "open",
                    write_plt: "write",
                    sleep_plt: "sleep",
                    exit_plt: "exit",
                    read_plt: "read"
                }
                target_addrs = [addr for addr in plt_to_syscall.keys() if addr is not None]

                for sysnum in [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]:
                    # Construct rsi value using sys, sysnum, and register d
                    rsi_val = construct_arg(ins_pos, arg1_pos, arg2_pos, sys, sysnum, result["register"]["d"])
                    base_addr = 0x2000000
                    dummy_ret_addr = 0xdeadbeef
                    init_register = {'a': 0, 'b': 100, 'c': 200}
                    simgr = simulate(interpret_sys, base_addr, claripy.BVV(rsi_val, 32), init_register, {}, dummy_ret_addr, target_addrs + [dummy_ret_addr])
                    if simgr.found:
                        found_state = simgr.found[0]
                        reached_addr = found_state.addr
                        if reached_addr in plt_to_syscall:
                            syscall_name = plt_to_syscall[reached_addr]
                            if syscall_name != 'read':
                                    
                                result["syscall"][syscall_name] = sysnum
                                print(f"Found identifier for '{syscall_name}': 0x{sysnum:x}")
                            else:
                                # Print register values for read syscall
                                try:
                                    rdx_val = found_state.solver.eval(found_state.regs.rdx)
                                    if rdx_val == init_register['c']:
                                        result["syscall"]["read_code"] = sysnum
                                        print(f"Found identifier for 'read_code': 0x{sysnum:x}")
                                    else:
                                        result["syscall"]["read_memory"] = sysnum
                                        print(f"Found identifier for 'read_memory': 0x{sysnum:x}")

                                except (angr.errors.SimUnconstrainedError, angr.errors.SimError) as e:
                                    print(f"Syscall 'read' for sysnum=0x{sysnum:x}: Error evaluating registers - {e}")

            else:
                print("\n[!] Warning: Cannot identify syscalls")

             
        def find_interpret_add(ins_pos, arg1_pos, arg2_pos):
            for interpret_add, add in tmp_result_instruction.items(): 
                rsi_val = construct_arg(ins_pos, arg1_pos, arg2_pos, add, result["register"]["a"], result["register"]["b"])
                base_addr = 0x2000000 
                init_register = {"a": 0xaa, "b": 0x2}
                simgr = simulate(interpret_add, base_addr, claripy.BVV(rsi_val, 32), init_register, {}, 0xdeadbeef, 0xdeadbeef)
                if simgr.found:
                    found_state = simgr.found[0]
                    mem_byte_val = get_mem_byte_val(found_state, base_addr, REG_TO_OFFSET["a"])
                    
                    if mem_byte_val == init_register["a"] + init_register["b"]:
                        print(f"Found interpret_add at 0x{interpret_add:x}, with identifier: 0x{add:x}")
                        result["instruction"]["add"] = add 
                        self.binary_loader.symbols["interpret_add"] = self.binary_loader.symbols.pop(f"sub_{interpret_add:x}")
                        tmp_result_instruction.pop(interpret_add)
                        return
            print("\n[!] Warning: Cannot find interpret_add")
        
        def find_interpret_stk(ins_pos, arg1_pos, arg2_pos):
            for interpret_stk, stk in tmp_result_instruction.items(): 
                rsi_val = construct_arg(ins_pos, arg1_pos, arg2_pos, stk, 0, result["register"]["a"])
                init_register = {"s": 0}
                base_addr = 0x2000000
                simgr = simulate(interpret_stk, base_addr, claripy.BVV(rsi_val, 32), init_register, {}, 0xdeadbeef, 0xdeadbeef)
                
                if simgr.found:
                    found_state = simgr.found[0]
                    mem_byte_val = get_mem_byte_val(found_state, base_addr, REG_TO_OFFSET["s"])
                    if mem_byte_val == 1:
                        print(f"Found interpret_stk at 0x{interpret_stk:x}, with identifier: 0x{stk:x}")
                        result["instruction"]["stk"] = stk
                        self.binary_loader.symbols["interpret_stk"] = self.binary_loader.symbols.pop(f"sub_{interpret_stk:x}")
                        tmp_result_instruction.pop(interpret_stk)
                        return
            print("\n[!] Warning: Cannot find interpret_stk")
        
        def find_interpret_stm(ins_pos, arg1_pos, arg2_pos):
            for interpret_stm, stm in tmp_result_instruction.items():
                rsi_val = construct_arg(ins_pos, arg1_pos, arg2_pos, stm, result["register"]["a"], result["register"]["b"])
                init_register = {"a": 0, "b": 0xcc}
                base_addr = 0x2000000
                simgr = simulate(interpret_stm, base_addr, claripy.BVV(rsi_val, 32), init_register, {}, 0xdeadbeef, 0xdeadbeef)
                if simgr.found:
                    found_state = simgr.found[0]
                    mem_byte_val = get_mem_byte_val(found_state, base_addr, 768)
                    if mem_byte_val == init_register["b"]:
                        print(f"Found interpret_stm at 0x{interpret_stm:x}, with identifier: 0x{stm:x}")
                        result["instruction"]["stm"] = stm
                        self.binary_loader.symbols["interpret_stm"] = self.binary_loader.symbols.pop(f"sub_{interpret_stm:x}")
                        tmp_result_instruction.pop(interpret_stm)
                        return
            print("\n[!] Warning: Cannot find interpret_stm")
                        
        def find_interpret_ldm(ins_pos, arg1_pos, arg2_pos):
            for interpret_ldm, ldm in tmp_result_instruction.items():
                rsi_val = construct_arg(ins_pos, arg1_pos, arg2_pos, ldm, result["register"]["a"], result["register"]["b"])
                init_register = {"a": 0xbb, "b": 1}
                init_memory = [(768 + 1, 0xcc)]
                base_addr = 0x2000000
                simgr = simulate(interpret_ldm, base_addr, claripy.BVV(rsi_val, 32), init_register, init_memory, 0xdeadbeef, 0xdeadbeef)
                if simgr.found:
                    found_state = simgr.found[0]
                    mem_byte_val = get_mem_byte_val(found_state, base_addr, REG_TO_OFFSET["a"]) 
                    if mem_byte_val == 0xcc:
                        print(f"Found interpret_ldm at 0x{interpret_ldm:x}, with identifier: 0x{ldm:x}")
                        result["instruction"]["ldm"] = ldm
                        self.binary_loader.symbols["interpret_ldm"] = self.binary_loader.symbols.pop(f"sub_{interpret_ldm:x}")
                        tmp_result_instruction.pop(interpret_ldm)
                        return
            print("\n[!] Warning: Cannot find interpret_ldm")

        def find_interpret_jmp(ins_pos, arg1_pos, arg2_pos):
            for interpret_jmp, jmp in tmp_result_instruction.items():
                rsi_val = construct_arg(ins_pos, arg1_pos, arg2_pos, jmp, 0, result["register"]["b"])
                init_register = {"b": 0xcc}
                base_addr = 0x2000000
                simgr = simulate(interpret_jmp, base_addr, claripy.BVV(rsi_val, 32), init_register, {}, 0xdeadbeef, 0xdeadbeef)
                if simgr.found:
                    found_state = simgr.found[0]
                    mem_byte_val = get_mem_byte_val(found_state, base_addr, REG_TO_OFFSET["i"])
                    if mem_byte_val == init_register["b"]:
                        print(f"Found interpret_jmp at 0x{interpret_jmp:x}, with identifier: 0x{jmp:x}")
                        result["instruction"]["jmp"] = jmp
                        self.binary_loader.symbols["interpret_jmp"] = self.binary_loader.symbols.pop(f"sub_{interpret_jmp:x}")
                        tmp_result_instruction.pop(interpret_jmp)
                        return   
            print("\n[!] Warning: Cannot find interpret_jmp")
        
        def find_interpret_cmp(ins_pos, arg1_pos, arg2_pos):
            for interpret_cmp, cmp in tmp_result_instruction.items():
                rsi_val = construct_arg(ins_pos, arg1_pos, arg2_pos, cmp, result["register"]["a"], result["register"]["b"])
                init_register = {"a": 0, "b": 0xcc}
                base_addr = 0x2000000
                simgr = simulate(interpret_cmp, base_addr, claripy.BVV(rsi_val, 32), init_register, {}, 0xdeadbeef, 0xdeadbeef)
                if simgr.found:
                    found_state = simgr.found[0]
                    mem_byte_val = get_mem_byte_val(found_state, base_addr, REG_TO_OFFSET["f"])
                    if mem_byte_val != 0:
                        print(f"Found interpret_cmp at 0x{interpret_cmp:x}, with identifier: 0x{cmp:x}")
                        result["instruction"]["cmp"] = cmp
                        self.binary_loader.symbols["interpret_cmp"] = self.binary_loader.symbols.pop(f"sub_{interpret_cmp:x}")
                        tmp_result_instruction.pop(interpret_cmp)
                        return
            print("\n[!] Warning: Cannot find interpret_cmp")

        def find_interpret_sys(ins_pos, arg1_pos, arg2_pos):
            if len(tmp_result_instruction.items()) != 1:
                print("\n[!] Warning: Cannot find interpret_sys")
            else:
                interpret_sys, sys = list(tmp_result_instruction.items())[0]
                print(f"Found interpret_sys at 0x{interpret_sys:x}, with identifier: 0x{sys:x}")
                result["instruction"]["sys"] = sys
                self.binary_loader.symbols["interpret_sys"] = self.binary_loader.symbols.pop(f"sub_{interpret_sys:x}")
                tmp_result_instruction.pop(interpret_sys)

                        
        identify_register() 
        
        ins_pos = result["opcode-order"].get("ins")
        arg1_pos = result["opcode-order"].get("arg1")
        arg2_pos = result["opcode-order"].get("arg2")
        
        find_interpret_add(ins_pos, arg1_pos, arg2_pos)
        find_interpret_stk(ins_pos, arg1_pos, arg2_pos)
        find_interpret_stm(ins_pos, arg1_pos, arg2_pos)
        find_interpret_ldm(ins_pos, arg1_pos, arg2_pos)
        find_interpret_jmp(ins_pos, arg1_pos, arg2_pos)
        find_interpret_cmp(ins_pos, arg1_pos, arg2_pos)
        find_interpret_sys(ins_pos, arg1_pos, arg2_pos)
        
        identify_flags(ins_pos, arg1_pos, arg2_pos)
        identify_syscalls(ins_pos, arg1_pos, arg2_pos)
        

    def run_analysis(self):
        result = {
            "register": {},
            "instruction": {},
            "syscall": {},
            "flag": {},
            "opcode-order": {}
        }
        
        
        print("\n[+] Recovering interpret functions")
        interpret_funcs = self.get_interpret_funcs()
     
        self.symbols_recovery(result, interpret_funcs)
        self.save_result(result)
        