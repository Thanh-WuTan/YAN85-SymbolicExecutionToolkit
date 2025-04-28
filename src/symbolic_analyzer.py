import claripy
import angr
import claripy

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

        # Test each edi value
        for edi in edi_values: 
            # Create a dummy return address
            dummy_ret_addr = 0xdeadbeef  # Arbitrary address not in the binary

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
        print(result['register'])