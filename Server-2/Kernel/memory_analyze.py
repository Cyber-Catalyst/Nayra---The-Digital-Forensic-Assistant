import argparse
import json
import re
import os

class MemoryAnalyzer:
    def __init__(self, dump_path):
        self.dump_path = dump_path
        self.dump_data = b''
        self.results = {}

    def read_memory_dump(self):
        """Read the raw memory dump into binary data."""
        try:
            with open(self.dump_path, "rb") as f:
                self.dump_data = f.read()
            print(f"[+] Loaded {len(self.dump_data)} bytes from memory dump.")
        except Exception as e:
            print(f"[-] Error reading memory dump: {e}")

    def detect_os(self):
        """Enhanced OS detection by checking multiple key signatures."""
        windows_signatures = [b"SystemRoot", b"Windows", b"\\Registry\\", b"\\WINDOWS\\System32"]
        linux_signatures = [b"/bin/bash", b"/usr/bin/", b"\x7fELF", b"/proc/", b"/sys/"]

        windows_matches = sum(1 for sig in windows_signatures if sig in self.dump_data)
        linux_matches = sum(1 for sig in linux_signatures if sig in self.dump_data)

        if windows_matches > linux_matches:
            return "Windows"
        elif linux_matches > windows_matches:
            return "Linux"
        return "Unknown"

    def find_process_names(self):
        """Extract process names from the memory dump (Windows)."""
        process_names = re.findall(rb"[a-zA-Z0-9_-]+\.exe", self.dump_data)
        unique_processes = list(set(process_names))
        self.results['processes'] = [p.decode('utf-8', errors='ignore') for p in unique_processes]

    def generate_report(self, output_file):
        """Generate a JSON forensic report."""
        try:
            with open(output_file, "w") as report_file:
                json.dump(self.results, report_file, indent=4)
            print(f"[+] Report saved to {output_file}")
        except Exception as e:
            print(f"[-] Failed to save report: {e}")


def main():
    parser = argparse.ArgumentParser(description="Memory Analyzer CLI for Forensic Investigation")
    parser.add_argument("-f", "--file", required=True, help="Path to the memory dump file")
    parser.add_argument("-o", "--output", default="report.json", help="Output file for analysis report")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("[-] Error: Memory dump file not found.")
        return

    analyzer = MemoryAnalyzer(args.file)
    analyzer.read_memory_dump()
    detected_os = analyzer.detect_os()
    print(f"[+] Detected OS: {detected_os}")

    if detected_os == "Windows":
        analyzer.find_process_names()
    else:
        print("[!] OS not supported yet for detailed process analysis.")

    analyzer.generate_report(args.output)


if __name__ == "__main__":
    main()
