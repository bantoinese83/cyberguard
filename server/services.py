import ipaddress
import logging
import os
import re
import socket
import ssl

import dns.resolver
import phonenumbers
import requests
import speedtest
import whois
from dotenv import load_dotenv
from phonenumbers import geocoder, carrier
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])
logger = logging.getLogger(__name__)
console = Console()

# Load API keys from environment variables
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not ABUSEIPDB_API_KEY:
    logger.error("ABUSEIPDB_API_KEY is not set in the environment variables.")
    exit(1)


# Fetch user IP and location
def get_user_ip_info():
    try:
        response = requests.get("https://ipinfo.io/json")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def fetch_blacklist():
    """Fetches the blacklist from AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return [entry['ipAddress'] for entry in data['data']]
    except requests.HTTPError as http_err:
        logger.error("HTTP error occurred: %s", http_err)
    except requests.RequestException as req_err:
        logger.error("Request error occurred: %s", req_err)
    except Exception as err:
        logger.error("An unexpected error occurred: %s", err)
    return []


# Fetch the blocklist
BLACKLISTS = fetch_blacklist()


def ip_lookup(ip_address):
    """Provides information about an IP address."""
    try:
        ip = ipaddress.ip_address(ip_address)
        response = requests.get(f"http://ip-api.com/json/{ip}")
        response.raise_for_status()
        data = response.json()
        return data
    except ValueError:
        logger.error("Invalid IP address: %s", ip_address)
        return {"error": "Invalid IP address"}
    except requests.HTTPError as http_err:
        logger.error("HTTP error occurred: %s", http_err)
        return {"error": f"HTTP error: {http_err}"}
    except requests.RequestException as req_err:
        logger.error("Request error occurred: %s", req_err)
        return {"error": f"Request error: {req_err}"}
    except Exception as err:
        logger.error("An unexpected error occurred: %s", err)
        return {"error": f"Unexpected error: {err}"}


def trace_email(email_header):
    """Attempts to trace the origin of an email using headers."""
    try:
        # Extract 'Received' headers
        received_headers = re.findall(r"Received: from (.+?) by (.+?); (.+?)(?=\nReceived:|\Z)", email_header,
                                      re.IGNORECASE | re.DOTALL)
        if received_headers:
            trace_info = []
            for received_from, received_by, date in received_headers:
                trace_info.append({
                    "received_from": received_from.strip(),
                    "received_by": received_by.strip(),
                    "date": date.strip()
                })
            return {"trace": trace_info}
        else:
            logger.warning("No 'Received' headers found in email header")
            return {"error": "No 'Received' headers found"}
    except re.error as regex_err:
        logger.error("Regex error occurred: %s", regex_err)
        return {"error": f"Regex error: {regex_err}"}
    except Exception as err:
        logger.error("An unexpected error occurred: %s", err)
        return {"error": f"Unexpected error: {err}"}


def security_check(ip_address):
    """Checks if an IP address is on a blocklist."""
    if ip_address in BLACKLISTS:
        logger.warning("IP address %s found on a blacklist", ip_address)
        return {"blacklisted": True}
    else:
        return {"blacklisted": False}


def speed_test():
    """Performs an internet speed test using speedtest-cli."""
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        st.download()
        st.upload()
        results = st.results.dict()
        return results
    except speedtest.ConfigRetrievalError as config_err:
        logger.error("Speedtest configuration retrieval error: %s", config_err)
        return {"error": f"Speedtest configuration error: {config_err}"}
    except speedtest.SpeedtestException as st_err:
        logger.error("Speedtest error: %s", st_err)
        return {"error": f"Speedtest error: {st_err}"}
    except Exception as err:
        logger.error("An unexpected error occurred: %s", err)
        return {"error": f"Unexpected error: {err}"}


def phone_number_lookup(phone_number: str, region: str = 'US'):
    try:
        # Parse phone number
        parsed_number = phonenumbers.parse(phone_number, region)

        # Check if the number is valid
        if not phonenumbers.is_valid_number(parsed_number):
            return {"valid": False, "message": "Invalid phone number"}

        # Get the location and carrier information
        location = geocoder.description_for_number(parsed_number, 'en')
        phone_carrier = carrier.name_for_number(parsed_number, 'en')

        return {
            "valid": True,
            "phone_number": phone_number,
            "location": location,
            "carrier": phone_carrier
        }

    except phonenumbers.phonenumberutil.NumberParseException as e:
        return {"valid": False, "message": str(e)}
    except Exception as e:
        return {"error": str(e)}


def host_name_to_ip(host_name):
    try:
        ip_address = socket.gethostbyname(host_name)
        return {"host_name": host_name, "ip_address": ip_address}
    except socket.gaierror as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def proxy_check(ip_address):
    results = {
        "IP": ip_address,
        "rDNS": False,
        "WIMIA Test": False,
        "Tor Test": False,
        "Loc Test": False,
        "Header Test": False,
        "DNSBL Test": False
    }

    # rDNS Test
    try:
        rdns = socket.gethostbyaddr(ip_address)
        results["rDNS"] = bool(rdns)
    except socket.herror:
        results["rDNS"] = False

    # WIMIA Test (Check if IP is in a known proxy list using ipinfo.io)
    wimia_url = f"https://ipinfo.io/{ip_address}/privacy"
    try:
        wimia_response = requests.get(wimia_url)
        results["WIMIA Test"] = wimia_response.json().get("proxy", False)
    except requests.RequestException:
        results["WIMIA Test"] = False

    # Tor Test (Check if IP is a known Tor exit node using torproject.org)
    tor_url = f"https://check.torproject.org/torbulkexitlist"
    try:
        tor_response = requests.get(tor_url)
        tor_exit_nodes = tor_response.text.splitlines()
        results["Tor Test"] = ip_address in tor_exit_nodes
    except requests.RequestException:
        results["Tor Test"] = False

    # Loc Test (Check if IP location matches expected location using ipinfo.io)
    loc_url = f"https://ipinfo.io/{ip_address}/json"
    try:
        loc_response = requests.get(loc_url)
        loc_data = loc_response.json()
        results["Loc Test"] = loc_data.get("country") == "US"  # Example: Check if the country is US
    except requests.RequestException:
        results["Loc Test"] = False

    # Header Test (Check for proxy headers using httpbin.org)
    headers = {
        "X-Forwarded-For": ip_address,
        "X-Real-IP": ip_address
    }
    header_url = "https://httpbin.org/headers"
    try:
        header_response = requests.get(header_url, headers=headers)
        results["Header Test"] = "X-Forwarded-For" in header_response.json().get("headers", {})
    except requests.RequestException:
        results["Header Test"] = False

    # DNSBL Test (Check if IP is listed in DNSBL using abuseipdb.com)
    dnsbl_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
    headers = {
        'Key': os.getenv("ABUSEIPDB_API_KEY"),
        'Accept': 'application/json'
    }
    try:
        dnsbl_response = requests.get(dnsbl_url, headers=headers)
        results["DNSBL Test"] = dnsbl_response.json().get("data", {}).get("abuseConfidenceScore", 0) > 0
    except requests.RequestException:
        results["DNSBL Test"] = False

    return results


def reverse_dns_lookup(ip_address):
    """Provides the hostname for a given IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return {"ip_address": ip_address, "hostname": hostname}
    except socket.herror as e:
        return {"error": f"Reverse DNS lookup failed: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


def port_scan(ip_address, ports=None):
    if ports is None:
        ports = [80, 443, 22, 21, 25, 110, 143, 3306, 5432, 27017, 3389, 8080, 8443, 8888, 9090, 9200, 9300]
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return {"ip_address": ip_address, "open_ports": open_ports}


def email_validation(email):
    # Basic regex check for email format
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if not re.match(regex, email):
        return {"valid": False, "message": "Invalid email format"}

    # Extract domain from email
    domain = email.split('@')[1]

    # Check if the domain has MX records
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if mx_records:
            return {"valid": True, "message": "Valid email address"}
    except dns.resolver.NoAnswer:
        return {"valid": False, "message": "No MX records found for domain"}
    except dns.resolver.NXDOMAIN:
        return {"valid": False, "message": "Domain does not exist"}
    except Exception as e:
        return {"valid": False, "message": f"Error checking MX records: {str(e)}"}

    return {"valid": False, "message": "Invalid email address"}


def url_scan(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    api_url = f"https://www.virustotal.com/vtapi/v2/url/scan?apikey={api_key}&url={url}"
    response = requests.post(api_url)
    return response.json()


def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return {"error": str(e)}


def ssl_certificate_check(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
    return cert


def dns_lookup(domain):
    result = {}
    try:
        answers = dns.resolver.resolve(domain, 'A')
        result['A'] = [rdata.to_text() for rdata in answers]
    except dns.resolver.NoAnswer:
        result['A'] = []
    return result


def malware_url_check(url):
    api_key = os.getenv("MALWARE_API_KEY")
    api_url = f"https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={url}"
    response = requests.get(api_url)
    return response.json()


def mac_address_lookup(mac_address):
    api_url = f"https://api.macvendors.com/{mac_address}"
    response = requests.get(api_url)
    return response.text


def website_statistics(domain):
    """Retrieves website statistics using similarweb.com."""
    api_key = os.getenv("SIMILARWEB_API_KEY")  # Get your API key from similarweb.com
    if not api_key:
        return {"error": "SIMILARWEB_API_KEY not found in environment variables."}

    headers = {
        "Authorization": f"Bearer {api_key}"
    }

    # Ensure the domain is properly formatted
    domain = domain.replace("www.", "")

    try:
        response = requests.get(
            f"https://api.similarweb.com/v1/website/{domain}/traffic-and-engagement/overview?api_key={api_key}",
            headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        data = response.json()

        # Extract relevant information (customize as needed)
        stats = {
            "Global Rank": data.get("global_rank"),
            "Country Rank": data.get("country_rank"),
            "Total Visits": data.get("total_visits_last_month"),
            "Bounce Rate": data.get("bounce_rate"),
            "Average Visit Duration": data.get("average_visit_duration"),
            "Pages per Visit": data.get("pages_per_visit"),
        }
        return stats

    except requests.exceptions.RequestException as e:
        return {"error": f"Error fetching website statistics: {e}"}
    except KeyError as e:
        return {"error": f"Unexpected response format: Missing key {e}"}


def display_results(results):  # Updated display function
    """Displays results in a table format using rich."""
    if "error" in results:  # Handle errors gracefully
        console.print(f"[red]Error: {results['error']}[/red]")
        return

    table = Table(title="Results")
    for key, value in results.items():
        table.add_row(key, str(value))
    console.print(table)
