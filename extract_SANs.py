import ssl
import socket
from urllib.parse import urlparse
import argparse
import os
import re
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

def get_certificate_san(url, verify=True, timeout=5):
    # Parse the URL to extract the hostname
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    
    # Establish a connection to get the certificate
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(timeout)
    conn.connect((hostname, 443))
    
    # Get the certificate
    cert_bin = conn.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
    
    # Log the entire certificate
    logger.debug(f"Certificate for {url}:")
    logger.debug(cert)
    
    # Log all extensions in the certificate
    logger.debug(f"Extensions in the certificate for {url}:")
    for ext in cert.extensions:
        logger.debug(f"Extension OID: {ext.oid}, Name: {ext.oid._name}, Value: {ext.value}")
    
    # Extract SANs from the certificate
    san_list = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for san in ext.value:
            if isinstance(san, x509.DNSName):
                logger.debug(f"Found SAN: {san.value}")
                san_list.append(san.value)
    except x509.ExtensionNotFound:
        logger.debug(f"Subject Alternative Name extension not found in the certificate for {url}")
    
    # Close the connection
    conn.close()
    
    # Clean and filter SANs
    clean_san_list = [san.lstrip('*.') for san in san_list if is_valid_san(san)]
    logger.debug(f"Clean SAN list for {url}: {clean_san_list}")
    
    return clean_san_list

def is_valid_san(san):
    # Regex to validate domain names and IP addresses
    domain_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    )
    ip_regex = re.compile(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    )
    valid = bool(domain_regex.match(san) or ip_regex.match(san))
    logger.debug(f"Validating SAN: {san}, Valid: {valid}")
    return valid

def process_url(url, san_set, logger, verify=True, timeout=5):
    try:
        san_list = get_certificate_san(url, verify, timeout)
        if san_list:
            logger.info(f"URLs for {url}:")
            for san in san_list:
                logger.info(san)
                san_set.add(san)
            logger.info("")
        else:
            logger.info(f"No valid SANs found for {url}")
    except Exception as e:
        logger.error(f"Failed to process {url}: {e}")

def process_file(file_path, san_set, logger, verify=True, timeout=5):
    with open(file_path, 'r') as file:
        urls = file.readlines()
        for url in urls:
            url = url.strip()
            if url:
                process_url(url, san_set, logger, verify, timeout)

def save_to_file(output_file_path, san_set):
    sorted_san_list = sorted(san_set)
    with open(output_file_path, 'w') as output_file:
        for san in sorted_san_list:
            output_file.write(f"{san}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract SANs from SSL certificates")
    parser.add_argument("-u", "--url", help="Single URL to process")
    parser.add_argument("-f", "--file", help="Text file containing a list of URLs")
    parser.add_argument("-o", "--output", help="Output file path", default="output.txt")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable certificate and hostname verification")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for socket connections in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    output_dir = os.path.dirname(args.output)
    if output_dir:  # Only create directory if there is one
        os.makedirs(output_dir, exist_ok=True)
    
    log_file_path = os.path.splitext(args.output)[0] + "_log.txt"

    # Configure logging to file and console
    logger = logging.getLogger("SANExtractor")
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    formatter = logging.Formatter('%(message)s')

    # File handler
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    san_set = set()
    
    if args.url:
        process_url(args.url, san_set, logger, not args.insecure, args.timeout)
    elif args.file:
        process_file(args.file, san_set, logger, not args.insecure, args.timeout)
    else:
        print("Please provide either a single URL or a file containing URLs.")
    
    save_to_file(args.output, san_set)
