import nmap
import socket
import openpyxl
import os

class NmapScanner:
    def __init__(self, website, tool_name="nmaptool"):
        self.website = website
        self.tool_name = tool_name
        self.website_ip = None
        self.nm = nmap.PortScanner()
        self.report_data = {
            "Website Name": website,
            "Website IP": "",
            "Possible Running Webserver": "Unknown",
            "Services": []
        }
    
    def scan(self):
        try:
            self.website_ip = socket.gethostbyname(self.website)
            print(f"Scanning {self.website} ({self.website_ip})...")
            self.nm.scan(hosts=self.website_ip, arguments="-O")
            self.report_data["Website IP"] = self.website_ip
            if 'osmatch' in self.nm[self.website_ip] and self.nm[self.website_ip]['osmatch']:
                self.report_data["Possible Running Webserver"] = self.nm[self.website_ip]['osmatch'][0]['name']
            
            for proto in self.nm[self.website_ip].all_protocols():
                for port in self.nm[self.website_ip][proto].keys():
                    service_name = self.nm[self.website_ip][proto][port].get('name', "Unknown")
                    self.report_data["Services"].append({
                        "Service": service_name,
                        "Service Port": port,
                        "Protocol": proto,
                        "State": self.nm[self.website_ip][proto][port]['state']
                    })
        except Exception as e:
            print(f"Error scanning website: {e}")
            return None
        
        return self.report_data

    def save_to_excel(self):
        sanitized_website_name = self.website.replace(".", "_").replace("/", "_")
        filename = f"{sanitized_website_name}_{self.tool_name}.xlsx"
        report_dir = "Reports"
        
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        
        filepath = os.path.join(report_dir, filename)
        
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Nmap Scan Report"
        
        ws.append(["Website Name", self.report_data["Website Name"]])
        ws.append(["Website IP", self.report_data["Website IP"]])
        ws.append(["Possible Running Webserver", self.report_data["Possible Running Webserver"]])
        ws.append([])  # Empty row
        ws.append(["Service", "Service Port", "Protocol", "State"])
        
        for service in self.report_data["Services"]:
            ws.append([service["Service"], service["Service Port"], service["Protocol"], service["State"]])
        
        wb.save(filepath)
        print(f"Report saved as {filepath}")

if __name__ == "__main__":
    website = input("Enter website URL (without http/https): ")
    scanner = NmapScanner(website)
    report = scanner.scan()
    if report:
        scanner.save_to_excel()
