import sys
import re

def extract_ips_and_domains_from_file(filename):
    # Regex patterns
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE)
    domain_pattern = re.compile(r'(?<=\()\w[\w\-\.]*\.[a-zA-Z]{2,6}(?=\s\(FQDN\))')

    extracted_ips = set()      # Using a set to avoid duplicates
    extracted_domains = set()

    with open(filename, 'r') as file:
        for line in file:
            # Search for IP addresses in the current line
            ip_matches = ip_pattern.findall(line)
            if ip_matches:
                for ip in ip_matches:
                    if not any(nb in line for nb in ["/16", "/18", "/12", "/14", "/21", "/13", "/15", "/48"]):
                        extracted_ips.add(ip)

            # Search for domains in the current line
            domain_matches = domain_pattern.findall(line)
            for domain in domain_matches:
                extracted_domains.add(domain)

    print("Extracted IPs:")
    for ip in extracted_ips:
        print(ip)

    print("\nExtracted Domains:")
    for domain in extracted_domains:
        print(domain)

    return extracted_ips, extracted_domains

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <filename>")
        sys.exit(1)

    filename = sys.argv[1]
    extract_ips_and_domains_from_file(filename)
