import ipaddress
import logging
import os
import re
import socket
import ssl
from datetime import datetime, timedelta

import dns.resolver
import phonenumbers
import requests
import speedtest
import sqlalchemy as sa
import whois
from dotenv import load_dotenv
from phonenumbers import geocoder, carrier
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from sqlalchemy import Integer, String, create_engine, func, cast, Date, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, mapped_column

load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, handlers=[RichHandler()])
logger = logging.getLogger(__name__)
console = Console()

# Database setup (replace with your database details)
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL, echo=False)  # echo=True for debugging
Base = declarative_base()


class PageView(Base):
    __tablename__ = "page_views"

    id = mapped_column(Integer, primary_key=True)
    date = mapped_column(String)  # Store date as string
    count = mapped_column(Integer)

    def __repr__(self):
        return f"<PageView(date='{self.date}', count='{self.count}')>"


class VisitSession(Base):
    __tablename__ = "visit_sessions"

    id = mapped_column(Integer, primary_key=True)
    start_time = mapped_column(String)  # Store time as string
    end_time = mapped_column(String)  # Store time as string

    def __repr__(self):
        return f"<VisitSession(start_time='{self.start_time}', end_time='{self.end_time}')>"


class Visitor(Base):
    __tablename__ = "visitors"

    id = mapped_column(Integer, primary_key=True)
    ip_address = mapped_column(String)
    visit_date = mapped_column(String)  # Store date as string
    region = mapped_column(String)

    def __repr__(self):
        return f"<Visitor(ip_address='{self.ip_address}', visit_date='{self.visit_date}', region='{self.region}')>"


class AppStatistics(Base):
    __tablename__ = "app_statistics"

    id = mapped_column(Integer, primary_key=True)
    date = mapped_column(String)  # Store date as string
    daily_visitors = mapped_column(Integer)
    monthly_pageviews = mapped_column(Integer)
    weekly_pageviews = mapped_column(Integer)
    total_sites_linking = mapped_column(Integer)
    average_time_on_site = mapped_column(String)  # Store time as string
    top_visitor_regions = mapped_column(JSON)
    most_used_tool = mapped_column(String)

    def __repr__(self):
        return (
            f"<AppStatistics(date='{self.date}', daily_visitors='{self.daily_visitors}', "
            f"monthly_pageviews='{self.monthly_pageviews}', weekly_pageviews='{self.weekly_pageviews}', "
            f"average_time_on_site='{self.average_time_on_site}', top_visitor_regions='{self.top_visitor_regions}', "
            f"most_used_tool='{self.most_used_tool}')>"
        )


class ToolUsage(Base):
    __tablename__ = 'tool_usage'
    id = mapped_column(Integer, primary_key=True)
    tool_name = mapped_column(String)
    usage_count = mapped_column(Integer, default=0)  # Initialize to 0
    last_used = mapped_column(sa.DateTime)

    def __repr__(self):
        return f"<ToolUsage(tool_name='{self.tool_name}', usage_count='{self.usage_count}', last_used='{self.last_used}')>"


try:  # Wrap table creation in a try-except block for error handling
    Base.metadata.create_all(engine)
    logger.info("Database tables created/verified successfully!")
except sa.exc.OperationalError as e:
    logger.error(f"Database error: {e}")
    exit(1)  # Exit the app if database connection fails.

Session = sessionmaker(bind=engine)

# Load API keys from environment variables
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not ABUSEIPDB_API_KEY:
    logger.error("ABUSEIPDB_API_KEY is not set in the environment variables.")
    exit(1)


# Fetch user IP and location
def get_user_ip_info():
    try:
        response = requests.get("http://ip-api.com/json/")
        print(response.status_code)  # Add this line to check the status code
        print(response.text)  # Add this line to inspect the response content
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def fetch_blacklist():
    """Fetches the blacklist from AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return [entry["ipAddress"] for entry in data["data"]]
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
    """Provides information about an IP address (IPv4 or IPv6)."""
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
        received_headers = re.findall(
            r"Received: from (.+?) by (.+?); (.+?)(?=\nReceived:|\Z)",
            email_header,
            re.IGNORECASE | re.DOTALL,
        )
        if received_headers:
            trace_info = []
            for received_from, received_by, date in received_headers:
                trace_info.append(
                    {
                        "received_from": received_from.strip(),
                        "received_by": received_by.strip(),
                        "date": date.strip(),
                    }
                )
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
    blacklists = fetch_blacklist()
    if ip_address in blacklists:
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


def phone_number_lookup(phone_number: str, region: str = "US"):
    try:
        # Parse phone number
        parsed_number = phonenumbers.parse(phone_number, region)

        # Check if the number is valid
        if not phonenumbers.is_valid_number(parsed_number):
            return {"valid": False, "message": "Invalid phone number"}

        # Get the location and carrier information
        location = geocoder.description_for_number(parsed_number, "en")
        phone_carrier = carrier.name_for_number(parsed_number, "en")

        return {
            "valid": True,
            "phone_number": phone_number,
            "location": location,
            "carrier": phone_carrier,
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
        "DNSBL Test": False,
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
        results["Loc Test"] = (
                loc_data.get("country") == "US"
        )  # Example: Check if the country is US
    except requests.RequestException:
        results["Loc Test"] = False

    # Header Test (Check for proxy headers using httpbin.org)
    headers = {"X-Forwarded-For": ip_address, "X-Real-IP": ip_address}
    header_url = "https://httpbin.org/headers"
    try:
        header_response = requests.get(header_url, headers=headers)
        results["Header Test"] = "X-Forwarded-For" in header_response.json().get(
            "headers", {}
        )
    except requests.RequestException:
        results["Header Test"] = False

    # DNSBL Test (Check if IP is listed in DNSBL using abuseipdb.com)
    dnsbl_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
    headers = {"Key": os.getenv("ABUSEIPDB_API_KEY"), "Accept": "application/json"}
    try:
        dnsbl_response = requests.get(dnsbl_url, headers=headers)
        results["DNSBL Test"] = (
                dnsbl_response.json().get("data", {}).get("abuseConfidenceScore", 0) > 0
        )
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


def email_validation(email):
    # Basic regex check for email format
    regex = r"^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    if not re.match(regex, email):
        return {"valid": False, "message": "Invalid email format"}

    # Extract domain from email
    domain = email.split("@")[1]

    # Check if the domain has MX records
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
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
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "name_servers": w.name_servers,
        }
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
        answers = dns.resolver.resolve(domain, "A")
        result["A"] = [rdata.to_text() for rdata in answers]
    except dns.resolver.NoAnswer:
        result["A"] = []
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
    """Retrieves website statistics using Similarweb DigitalRank API (Free Version)."""
    api_key = os.getenv("SIMILARWEB_API_KEY")
    if not api_key:
        return {"error": "SIMILARWEB_API_KEY not found in environment variables."}

    # SimilarWeb recommends removing "www." for consistent results.
    domain = domain.replace("www.", "")

    try:
        url = f"https://api.similarweb.com/v1/similar-rank/{domain}/rank?api_key={api_key}"
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        if "error" in data:
            return {"error": data["error"]}

        # Data points charged
        data_points_charged = int(response.headers.get("sw-datapoint-charged", 0))

        stats = {
            "Global Rank": data.get("global_rank"),
            "Data Points Charged": data_points_charged,  # Include data points used
        }
        return stats

    except requests.exceptions.HTTPError as http_err:
        if (
                http_err.response.status_code == 404
        ):  # Handle 'Data not found' specifically.
            return {
                "error": f"Domain '{domain}' not found or does not have a global rank."
            }
        return {"error": f"HTTP error occurred: {http_err}"}  # More generic HTTP errors
    except requests.exceptions.RequestException as e:
        return {
            "error": f"Error fetching website statistics: {e}"
        }  # Catch other request errors
    except KeyError as e:
        return {"error": f"Unexpected response format: Missing key {e}"}
    except Exception as e:  # Very general exception for anything else unexpected.
        return {"error": f"An unexpected error occurred: {e}"}


def get_or_create_app_stats(session, today):
    """Gets or creates app stats for today."""
    date_str = today.strftime("%Y-%m-%d")
    stats = session.query(AppStatistics).filter(AppStatistics.date == date_str).first()
    if not stats:
        stats = AppStatistics()
        session.add(stats)
        session.commit()
    return stats


def app_statistics(days=1, use_cached=True):
    """Retrieves app usage statistics."""
    today = datetime.now().date()
    with Session() as session:
        stats = get_or_create_app_stats(
            session, today
        )  # Ensure a stat record exists for today
        most_used_tool = get_most_used_tool()  # Fetch the most used tool

        if use_cached and all(
                [
                    stats.daily_visitors,
                    stats.monthly_pageviews,
                    stats.weekly_pageviews,
                    stats.average_time_on_site,
                    stats.top_visitor_regions,
                ]
        ):  # Ensure there are existing stats
            return {
                "Daily Visitors": stats.daily_visitors,
                "Monthly Pageviews": stats.monthly_pageviews,
                "Weekly Pageviews": stats.weekly_pageviews,
                "Average Time On Site": stats.average_time_on_site,
                "Most Used Tool": stats.most_used_tool,  # Include most used tool
                "Top Visitor Regions": stats.top_visitor_regions,
            }

        # Update (if needed) and return
        updated_stats = update_statistics(session, days, today, stats)
        updated_stats["Most Used Tool"] = most_used_tool  # Add most used tool to stats
        return updated_stats


def get_top_visitor_regions(limit=5):
    """Gets the top visitor regions using SQLAlchemy."""
    try:
        with Session() as session:
            top_regions = (
                session.query(Visitor.region, func.count(Visitor.region).label("count"))
                .group_by(Visitor.region)
                .order_by(sa.desc("count"))
                .limit(limit)
                .all()
            )
            return [{"region": region, "count": count} for region, count in top_regions]
    except Exception as e:  # Keep general Exception for database errors.
        logger.error(f"Error fetching top visitor regions: {e}")
        return []


def update_statistics(session, days, today, stats_obj):
    start_date = today - timedelta(days=days)
    daily_visitors = get_daily_visitors(start_date, today) or 0
    monthly_pageviews = get_monthly_pageviews() or 0
    weekly_pageviews = get_weekly_pageviews() or 0
    average_time_on_site = calculate_avg_time_on_site() or "00:00:00"
    top_regions = get_top_visitor_regions(limit=5) or []
    top_tool = get_most_used_tool()  # Fetch the most used tool

    # Update the existing AppStatistics object instead of creating a new one
    stats_obj.daily_visitors = daily_visitors
    stats_obj.monthly_pageviews = monthly_pageviews
    stats_obj.weekly_pageviews = weekly_pageviews
    stats_obj.average_time_on_site = average_time_on_site
    stats_obj.top_visitor_regions = top_regions
    stats_obj.most_used_tool = top_tool

    try:
        session.commit()  # Save changes
    except Exception as e:
        session.rollback()
        logger.error(f"Error updating stats: {e}")
        return {"error": "Database error"}

    return {
        "Daily Visitors": stats_obj.daily_visitors,
        "Monthly Pageviews": stats_obj.monthly_pageviews,
        "Weekly Pageviews": stats_obj.weekly_pageviews,
        "Average Time On Site": stats_obj.average_time_on_site,
        "Top Visitor Regions": stats_obj.top_visitor_regions,
        "Most Used Tool": stats_obj.most_used_tool,
    }


def get_daily_visitors(start_date, end_date):
    try:
        with Session() as session:
            # Assuming Visitor.visit_date is a String, convert to Date for comparison
            total_visitors = (
                session.query(Visitor)
                .filter(
                    cast(Visitor.visit_date, Date) >= start_date,  # Convert to Date
                    cast(Visitor.visit_date, Date) <= end_date,  # Convert to Date
                )
                .count()
            )
            return total_visitors
    except Exception as e:
        logger.error(f"Error fetching daily visitors: {e}")
        return 0  # Return 0 on error


def get_monthly_pageviews():
    try:
        with Session() as session:
            today = datetime.now()
            first_day_of_month = today.replace(day=1)
            total_pageviews = (
                session.query(func.sum(PageView.count))
                .filter(cast(PageView.date, sa.DateTime) >= first_day_of_month)
                .scalar()
            )  # Use scalar() to get a single value
            return total_pageviews or 0  # Handle the case where no data is found
    except Exception as e:
        logger.error(f"Error fetching monthly pageviews: {e}")
        return 0


def get_weekly_pageviews():
    try:
        with Session() as session:
            today = datetime.now()
            first_day_of_week = today - timedelta(days=today.weekday())
            total_pageviews = (
                session.query(func.sum(PageView.count))
                .filter(cast(PageView.date, sa.DateTime) >= first_day_of_week)
                .scalar()
            )  # Use scalar() to get a single value
            return total_pageviews or 0  # Handle the case where no data is found
    except Exception as e:
        logger.error(f"Error fetching weekly pageviews: {e}")
        return 0


def calculate_avg_time_on_site():
    try:
        with Session() as session:
            # Example: Assuming you have a VisitSession model with start_time and end_time
            average_duration = session.query(
                func.avg(
                    cast(VisitSession.end_time, sa.DateTime)
                    - cast(VisitSession.start_time, sa.DateTime)
                )
            ).scalar()
            if average_duration:
                return str(average_duration)  # Convert timedelta to string
            return "00:00:00"

    except Exception as e:
        logger.error(f"Error calculating average time on site: {e}")
        return "00:00:00"


def track_tool_usage(tool_name):
    """Tracks tool usage in the database."""
    try:
        with Session() as session:
            tool = session.query(ToolUsage).filter_by(tool_name=tool_name).first()
            if tool:
                tool.usage_count += 1
                tool.last_used = datetime.now()  # Update last used timestamp
            else:
                tool = ToolUsage()  # Create new record for first use
                session.add(tool)
            session.commit()
    except Exception as e:
        logger.error(f"Error tracking tool usage: {e}")


def get_most_used_tool():
    """Retrieves the most used tool from the database."""
    try:
        with Session() as session:
            most_used_tool = (session.query(ToolUsage)
                              .order_by(ToolUsage.usage_count.desc(),
                                        ToolUsage.last_used.desc())  # Order by count, then last used
                              .first())
            if most_used_tool:
                return most_used_tool.tool_name
            return None  # Or a suitable default like "N/A"

    except Exception as e:  # Catch database errors
        logger.error(f"Error fetching most used tool: {e}")
        return None  # Or handle the error as needed


def display_results(results):  # Updated display function
    """Displays results in a table format using rich."""
    if "error" in results:  # Handle errors gracefully
        console.print(f"[red]Error: {results['error']}[/red]")
        return

    table = Table(title="Results")
    for key, value in results.items():
        table.add_row(key, str(value))
    console.print(table)
