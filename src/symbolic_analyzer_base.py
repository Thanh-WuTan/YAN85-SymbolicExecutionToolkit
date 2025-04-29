class SymbolicAnalyzer:
    def __init__(self, binary_loader):
        self.binary_loader = binary_loader
        self.project = binary_loader.project
        self.symbols = binary_loader.symbols

    def save_result(self, result):
        import os
        import yaml

        print("\n[+] Saving result to YAML file...")
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(base_dir, "result")
        os.makedirs(output_dir, exist_ok=True)

        output_file = os.path.join(output_dir, f"{self.binary_loader.binary_name}.yml")
        register_order = ["a", "b", "c", "d", "i", "s", "f"]
        if "register" in result:
            result["register"] = {key: result["register"][key] for key in register_order if key in result["register"]}
        try:
            with open(output_file, "w") as f:
                yaml.safe_dump(result, f, sort_keys=False, default_flow_style=False)
            print(f"[+] Result saved to {output_file}")
        except Exception as e:
            print(f"[!] Error writing result to {output_file}: {e}")

    def run_analysis(self):
        raise NotImplementedError("Subclasses must implement run_analysis()")