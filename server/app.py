import socket
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

from services import (
    ip_lookup,
    trace_email,
    security_check,
    speed_test,
    phone_number_lookup,
    proxy_check,
    reverse_dns_lookup,
    ssl_certificate_check,
    dns_lookup,
    whois_lookup,
    malware_url_check,
    mac_address_lookup,
    email_validation,
    website_statistics,
    app_statistics,
    track_visitor,
    track_page_view, track_tool_usage, )

# Load breach data

# Set page configuration
st.set_page_config(page_title="CyberGuard", layout="wide")

# Custom CSS for better styling
st.markdown(
    """
    <style>
    .main {
        background-color: #f0f2f6;
    }
    .sidebar .sidebar-content {
        background-color: #2c3e50;
        color: white;
    }
    .sidebar .sidebar-content a {
        color: #1abc9c;
    }
    .sidebar .sidebar-content a:hover {
        color: #16a085;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Display logo and title
st.sidebar.image("cyberguard_logo.png", width=100)

# --- Get and display app statistics in the header ---
with st.spinner("Loading app statistics..."):
    app_stats = app_statistics()  # Fetch the app statistics
    if "error" in app_stats:
        app_stats = (
            {}
        )  # Use an empty dictionary if fetching stats fails to prevent displaying an error on every
        # page load


# --- Fetch user IP and location (using a separate function to avoid Streamlit issues) ---
def fetch_user_ip_info():
    try:
        response = requests.get("http://ip-api.com/json/")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": str(e)}


user_ip_info = fetch_user_ip_info()
if "error" not in user_ip_info:
    track_visitor(user_ip_info.get('query', 'N/A'), user_ip_info.get('regionName', 'N/A'))

# Call the page view tracking function
track_page_view()

user_ip_info = fetch_user_ip_info()

# --- Initialize session state ---
if 'app_stats' not in st.session_state:
    st.session_state.app_stats = {}


# --- Define function to update app statistics ---
def update_app_stats():
    st.session_state.app_stats = app_statistics(use_cached=False)


# --- Display app statistics in the header ---
st.title("CyberGuard")

col1, col2, col3, col4, col5, col6 = st.columns(6)

# Use session state to access updated statistics
col1.metric("👥 Daily Visitors", st.session_state.app_stats.get("Daily Visitors", "N/A"))
col2.metric("📅 Monthly Pageviews", st.session_state.app_stats.get("Monthly Pageviews", "N/A"))
col3.metric("📈 Weekly Pageviews", st.session_state.app_stats.get("Weekly Pageviews", "N/A"))
col4.metric("⏱️ Average Time On Site", st.session_state.app_stats.get("Average Time On Site", "N/A"))
col5.metric("🌍 Top Visiting Region", st.session_state.app_stats.get("Top Visiting Region", "N/A"))
col6.metric("🔗 Crowd Favorite Tool", st.session_state.app_stats.get("Most Used Tool", "N/A"))

# Sidebar navigation
st.sidebar.title("🔍 Navigation")
current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
st.sidebar.write(f"**Current Time:** {current_time}")

if "error" not in user_ip_info:
    if "query" in user_ip_info:
        st.sidebar.markdown(
            f"**IPv4:** <span style='background-color: black; padding: 2px 4px;'>{user_ip_info['query']}</span>",
            unsafe_allow_html=True)
    if "ip_v6" in user_ip_info:
        st.sidebar.markdown(
            f"**IPv6:** <span style='background-color: red; padding: 2px 4px;'>{user_ip_info['ip_v6']}</span>",
            unsafe_allow_html=True)

    st.sidebar.write(
        f"**Location:** {user_ip_info['city']}, {user_ip_info['regionName']}, {user_ip_info['country']}"
    )

    # Display the location on a small map if latitude and longitude are available
    if "lat" in user_ip_info and "lon" in user_ip_info:
        lat, lon = user_ip_info["lat"], user_ip_info["lon"]
        location_df = pd.DataFrame({"lat": [lat], "lon": [lon]})
        st.sidebar.map(location_df, zoom=10)
else:
    st.sidebar.write("Unable to fetch IP information")

tool = st.sidebar.radio(
    "Go to",
    [
        "🌐 IP Lookup",
        "📧 Email Trace",
        "🔒 Security Check",
        "📶 Internet Speed Test",
        "📞 Phone Number Lookup",
        "🔍 Host Name to IP",
        "🛡️ Proxy Check",
        "🔄 Reverse DNS Lookup",
        "✅ Email Validation",
        "🔎 MAC Address Lookup",
        "🔏 SSL Certificate Check",
        "🌐 DNS Lookup",
        "🔍 WHOIS Lookup",
        "🛡️ Malware URL Check",
        "📊 Website Statistics",
    ],
)

st.header("🔐 IP and Email Security Tool")


# --- Helper Function for Display ---
def display_results(results):
    """Displays results in a table format using Streamlit."""
    if "error" in results:
        st.error(f"Error: {results['error']}")
        return

    # Convert all list values to strings
    for key, value in results.items():
        if isinstance(value, list):
            results[key] = ', '.join(map(str, value))

    # Create DataFrame
    results_df = pd.DataFrame(list(results.items()), columns=['Attribute', 'Value'])
    st.table(results_df.set_index('Attribute'))

    if isinstance(results, dict):
        pd.DataFrame(results.items(), columns=["Attribute", "Details"])
    elif isinstance(results, list):
        if all(isinstance(item, dict) for item in results):
            pd.DataFrame(results)
        else:
            st.error("List items are not dictionaries.")
            return
    else:
        st.error("Unsupported results format.")
        return


# --- Tools ---
if tool == "🌐 IP Lookup":
    st.subheader("IP Lookup 🔍")
    st.write(
        """
    This tool provides detailed information about an IP address, including its geolocation, ISP, and potential blacklist status.

    **How it works:**

    1. **Input:** Enter the IP address you'd like to investigate.
    2. **Lookup:** Click the "Lookup" button.  The tool will query various databases and services to gather information.
    3. **Results:** The results will be displayed in a table and on a map (if location data is available).


    **What you'll get:**

    - IP Address
    - City, Region, Country, Postal Code
    - Latitude and Longitude (for mapping)
    - Timezone
    - Organization and ASN
    - ISP (Internet Service Provider)
    - Blacklist status (check against known malicious IP lists)


    **How to find someone's IP address (if needed):**
    There are several ways to find someone's IP address, but it's important to respect privacy and legal regulations. 
    See these resources for information:

    - [11 Ways To Get Someone's IP Address](https://whatismyipaddress.com/get-ip)
    - Searching "What is my IP address?" on Google will show your own public IP.


    """
    )  # Using triple quotes for multiline string

    ip_address = st.text_input("Enter IP address")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up IP..."):
            ip_info = ip_lookup(ip_address)
            blacklist_info = security_check(ip_address)
            speed_info = speed_test()

        if "error" in ip_info:
            st.error(ip_info["error"])
        else:
            combined_info = {**ip_info, **blacklist_info, **speed_info}
            display_results(combined_info)

            # Display the location on a map if latitude and longitude are available
            if "lat" in ip_info and "lon" in ip_info:
                location_df = pd.DataFrame(
                    {"lat": [float(ip_info["lat"])], "lon": [float(ip_info["lon"])]}
                )
                st.map(location_df)
            else:
                st.warning("Location data not available for this IP address.")

    # Store tool usage in session state
    if 'tool_usage' not in st.session_state:
        st.session_state.tool_usage = {}
    st.session_state.tool_usage["IP Lookup"] = st.session_state.tool_usage.get("IP Lookup", 0) + 1
    track_tool_usage("IP Lookup")  # Also track in the database

elif tool == "📧 Email Trace":
    st.subheader("Email Trace ✉️")
    st.write(
        """
    Trace the route of an email using its headers. This can help identify the sender's location, mail servers involved, and potential spoofing or relaying.

    **How it works:**

    1. **Get email headers:** Retrieve the full headers from your email client. See instructions for your specific email provider. [Here's a general guide.](https://mxtoolbox.com/Public/Content/EmailHeaders/)
    2. **Paste headers:** Paste the copied email headers into the text area below.
    3. **Trace:** Click the "Trace" button. The tool will parse the headers and display the email's path.

    **What you'll get:**

    - **Received From:** The server that received the email.
    - **Received By:** The server that sent the email.
    - **Date:** The date and time of the email transmission.
    
    """
    )

    email_header = st.text_area(
        "Enter email header",
        placeholder="Received: from mac.com ([10.13.11.252])\n  by "
                    "ms031.mac.com (Sun Java System Messaging Server "
                    "6.2-8.04 (built Feb 28 2007)) with ESMTP id "
                    "<0JMI007ZN7PETGC0@ms031.mac.com> for "
                    "user@example.com; Thu, 09 Aug 2007 04:24:50 -0700 "
                    "(PDT)\nReceived: from mail.dsis.net (mail.dsis.net "
                    "[70.183.59.5])\n  by mac.com ("
                    "Xserve/smtpin22/MantshX 4.0) with ESMTP id "
                    "l79BOnNS000101\n  for <user@example.com>; Thu, "
                    "09 Aug 2007 04:24:49 -0700 (PDT)\nReceived: from ["
                    "192.168.2.77] (70.183.59.6) by mail.dsis.net with "
                    "ESMTP\n  (EIMS X 3.3.2) for <user@example.com>; "
                    "Thu, 09 Aug 2007 04:24:49 -0700",
    )
    if st.button("🔍 Trace"):
        with st.spinner("Tracing email..."):
            email_trace = trace_email(email_header)
        if "error" in email_trace:
            st.error(email_trace["error"])
        else:
            st.write("### Email Trace Results")
            for trace in email_trace.get("trace", []):
                st.write(f"**Received From:** {trace['received_from']}")
                st.write(f"**Received By:** {trace['received_by']}")
                st.write(f"**Date:** {trace['date']}")
                st.markdown("---")

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}
            st.session_state.tool_usage["Email Trace"] = st.session_state.tool_usage.get("Email Trace", 0) + 1
            track_tool_usage("Email Trace")  # Also track in the database


elif tool == "🔒 Security Check":
    st.subheader("🔒 Security Check")
    st.write(
        """
    This tool checks if an IP address is listed on known blocklists, helping identify potentially malicious actors.

    **How it works:**

    1. **Input:** Enter the IP address you want to check for security in the text input field.
    2. **Check:** Click the "🔍 Check" button. The tool will query various blocklists and security databases.
    3. **Results:** The results will be displayed in JSON format, showing whether the IP address is blacklisted or not.

    **What you'll get:**

    - **Blacklisted Status:** Indicates if the IP address is found on any known blocklists.
    - **Detailed Information:** Additional details about the IP address, if available.
    """
    )

    ip_address_check = st.text_input("Enter IP address for security check")
    if st.button("🔍 Check"):
        with st.spinner("Checking security..."):
            security_status = security_check(ip_address_check)
        if "error" in security_status:
            st.error(security_status["error"])
        else:
            st.metric(
                label="Blacklisted",
                value="Yes" if security_status["blacklisted"] else "No",
            )

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}
            st.session_state.tool_usage["Security Check"] = st.session_state.tool_usage.get("Security Check", 0) + 1
            track_tool_usage("Security Check")  # Also track in the database


elif tool == "📶 Internet Speed Test":
    st.subheader("📶 Internet Speed Test")
    st.write(
        """
    This tool measures your internet connection's download and upload speeds, along with ping times.

    **How it works:**

    1. **Run Test:** Click the "Run Test" button to start the speed test.
    2. **Measure:** The tool will measure your internet connection's download and upload speeds.
    3. **Results:** The results will be displayed in a user-friendly format.

    **What you'll get:**

    - **Download Speed:** The rate at which data is downloaded from the internet to your device.
    - **Upload Speed:** The rate at which data is uploaded from your device to the internet.
    - **Ping:** The time it takes for a data packet to travel from your device to the server and back.
    - **Server Information:** Details about the server used for the speed test.
    - **Client Information:** Details about your device's connection.
    """
    )

    if st.button("🏃‍♂️ Run Test"):
        with st.spinner("Running speed test..."):
            speedtest_results = speed_test()
        if "error" in speedtest_results:
            st.error(speedtest_results["error"])
        else:
            st.subheader("📊 Speed Test Results")

            # Display key metrics
            col1, col2, col3 = st.columns(3)
            col1.metric(
                label="Download Speed",
                value=f"{speedtest_results['download'] / 1_000_000:.2f} Mbps",
            )
            col2.metric(
                label="Upload Speed",
                value=f"{speedtest_results['upload'] / 1_000_000:.2f} Mbps",
            )
            col3.metric(label="Ping", value=f"{speedtest_results['ping']} ms")

            # Display server information
            st.write("### Server Information")
            server_info = speedtest_results["server"]
            st.write(
                f"Server: {server_info['name']}, {server_info['country']} ({server_info['sponsor']})"
            )
            st.write(f"Server Latency: {server_info['latency']} ms")

            # Display client information
            st.write("### Client Information")
            client_info = speedtest_results["client"]
            st.write(f"Client IP: {client_info['ip']}")
            st.write(f"Client ISP: {client_info['isp']}")
            st.write(f"Client Country: {client_info['country']}")
            st.write(f"Client Location: {client_info['lat']}, {client_info['lon']}")

            # Create gauge charts and place them in columns
            col1, col2, col3 = st.columns(3)

            with col1:
                fig = go.Figure(
                    go.Indicator(
                        mode="gauge+number",
                        value=speedtest_results["download"] / 1_000_000,
                        title={"text": "Download Speed (Mbps)"},
                        gauge={"axis": {"range": [None, 1000]}},
                    )
                )
                st.plotly_chart(fig)

            with col2:
                fig = go.Figure(
                    go.Indicator(
                        mode="gauge+number",
                        value=speedtest_results["upload"] / 1_000_000,
                        title={"text": "Upload Speed (Mbps)"},
                        gauge={"axis": {"range": [None, 1000]}},
                    )
                )
                st.plotly_chart(fig)

            with col3:
                fig = go.Figure(
                    go.Indicator(
                        mode="gauge+number",
                        value=speedtest_results["ping"],
                        title={"text": "Ping (ms)"},
                        gauge={"axis": {"range": [None, 100]}},
                    )
                )
                st.plotly_chart(fig)

            # Display server location on a map
            server_location = pd.DataFrame(
                {"lat": [float(server_info["lat"])], "lon": [float(server_info["lon"])]}
            )
            st.map(server_location)

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}
            st.session_state.tool_usage["Internet Speed Test"] = st.session_state.tool_usage.get("Internet Speed Test",
                                                                                                 0) + 1
            track_tool_usage("Internet Speed Test")  # Also track in the database

elif tool == "📞 Phone Number Lookup":
    st.subheader("📞 Phone Number Lookup")
    st.write(
        """
    This tool provides location and carrier information for a given phone number.

    **How it works:**

    1. **Input:** Enter the phone number you want to look up in the text input field.
    2. **Lookup:** Click the "🔍 Lookup" button. The tool will query various databases to gather information.
    3. **Results:** The results will be displayed in a table and on a map (if location data is available).

    **What you'll get:**

    - Validation Status: Indicates if the phone number is valid.
    - Location: The geographical location associated with the phone number.
    - Carrier: The carrier information for the phone number.
    - Map: A map showing the location if available.
    """
    )

    phone_number = st.text_input("Enter phone number", placeholder="e.g., +1234567890")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up phone number..."):
            phone_info = phone_number_lookup(phone_number)

        if "error" in phone_info:
            st.error(phone_info["error"])
        else:
            display_results(phone_info)

            # Display the location on a map if location information is available
            if "location" in phone_info and phone_info["location"]:
                location = phone_info["location"]
                st.write(f"Location: {location}")

                # Use OpenCage Geocoding API to get lat/lon from the location string
                api_key = "c75bc92cf5b94dfaa85324e05020e9a8"
                geocode_url = f"https://api.opencagedata.com/geocode/v1/json?q={location}&key={api_key}"
                try:
                    geocode_response = requests.get(geocode_url)
                    geocode_response.raise_for_status()
                    geocode_data = geocode_response.json()
                    if geocode_data and geocode_data["results"]:
                        lat = geocode_data["results"][0]["geometry"]["lat"]
                        lon = geocode_data["results"][0]["geometry"]["lng"]
                        location_df = pd.DataFrame({"lat": [lat], "lon": [lon]})
                        st.map(location_df)
                    else:
                        st.warning("Geocoding service did not return any results.")
                except requests.RequestException as e:
                    st.error(f"Error fetching geocoding data: {e}")

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}
            st.session_state.tool_usage["Phone Number Lookup"] = st.session_state.tool_usage.get("Phone Number Lookup",
                                                                                                 0) + 1
            track_tool_usage("Phone Number Lookup")  # Also track in the database

elif tool == "🔍 Host Name to IP":
    st.subheader("🔍 Host Name to IP")
    st.write(
        """
    This tool converts a hostname (e.g., www.example.com) to its corresponding IP address.

    **How it works:**

    1. **Input:** Enter the host name you want to look up in the text input field.
    2. **Lookup:** Click the "🔍 Lookup" button. The tool will resolve the hostname to its IP address.
    3. **Results:** The IP address information will be displayed in a table.

    **What you'll get:**

    - **Host Name:** The hostname you entered.
    - **IP Address:** The resolved IP address of the hostname.
    """
    )

    host_name = st.text_input("Enter host name", placeholder="e.g., www.example.com")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up host name..."):
            try:
                host_ip = socket.gethostbyname(host_name)
                host_ip_info = {"host_name": host_name, "ip_address": host_ip}
                display_results(host_ip_info)
            except socket.gaierror as e:
                st.error(f"Error looking up host name: {e}")

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["Host Name to IP"] = st.session_state.tool_usage.get("Host Name to IP", 0) + 1
            track_tool_usage("Host Name to IP")  # Also track in the database

elif tool == "🛡️ Proxy Check":
    st.subheader("🛡️ Proxy Check")
    st.write(
        """
    This tool checks if an IP address is associated with a proxy server.

    **How it works:**

    1. **Input:** Enter the IP address you want to check for proxy in the text input field.
    2. **Check:** Click the "🔍 Check" button. The tool will perform various tests to determine if the IP address is a proxy.
    3. **Results:** The proxy check results will be displayed in a table.

    **What you'll get:**

    - **IP:** The IP address you entered.
    - **rDNS:** Indicates if reverse DNS lookup was successful.
    - **WIMIA Test:** Indicates if the IP is in a known proxy list.
    - **Tor Test:** Indicates if the IP is a known Tor exit node.
    - **Loc Test:** Indicates if the IP location matches the expected location.
    - **Header Test:** Indicates if proxy headers were detected.
    - **DNSBL Test:** Indicates if the IP is listed in DNSBL.
    """
    )

    ip_address_proxy = st.text_input("Enter IP address for proxy check")
    if st.button("🔍 Check"):
        with st.spinner("Checking proxy..."):
            proxy_results = proxy_check(ip_address_proxy)
        if "error" in proxy_results:
            st.error(proxy_results["error"])
        else:
            display_results(proxy_results)

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["Proxy Check"] = st.session_state.tool_usage.get("Proxy Check", 0) + 1
            track_tool_usage("Proxy Check")  # Also track in the database

elif tool == "🔄 Reverse DNS Lookup":
    st.subheader("🔄 Reverse DNS Lookup")
    st.write(
        """
    This tool provides the hostname for a given IP address.

    **How it works:**

    1. **Input:** Enter the IP address you want to look up in the text input field.
    2. **Lookup:** Click the "🔍 Lookup" button. The tool will perform a reverse DNS lookup.
    3. **Results:** The reverse DNS lookup results will be displayed in a table.

    **What you'll get:**

    - **IP Address:** The IP address you entered.
    - **Hostname:** The resolved hostname of the IP address.
    """
    )

    ip_address_reverse_dns = st.text_input("Enter IP address for reverse DNS lookup")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up reverse DNS..."):
            reverse_dns_results = reverse_dns_lookup(ip_address_reverse_dns)
        if "error" in reverse_dns_results:
            st.error(reverse_dns_results["error"])
        else:
            display_results(reverse_dns_results)

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["Reverse DNS Lookup"] = st.session_state.tool_usage.get("Reverse DNS Lookup",
                                                                                                0) + 1
            track_tool_usage("Reverse DNS Lookup")  # Also track in the database

elif tool == "✅ Email Validation":
    st.subheader("✅ Email Validation")
    st.write(
        """
    This tool validates the format and domain of an email address.

    **How it works:**

    1. **Input:** Enter the email address you want to validate in the text input field.
    2. **Validate:** Click the "🔍 Validate" button. The tool will check the email format and domain validity.
    3. **Results:** The validation results will be displayed in a table.

    **What you'll get:**

    - **Validation Status:** Indicates if the email address is valid.
    - **Message:** Provides additional information about the validation result.
    """
    )

    email = st.text_input("Enter email address")
    if st.button("🔍 Validate"):
        with st.spinner("Validating email..."):
            email_validation_result = email_validation(email)
        if "error" in email_validation_result:
            st.error(email_validation_result["error"])
        else:
            st.metric(
                label="Validation Status",
                value="Valid" if email_validation_result["valid"] else "Invalid",
            )
            st.write(f"**Message:** {email_validation_result['message']}")

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["Email Validation"] = st.session_state.tool_usage.get("Email Validation", 0) + 1
            track_tool_usage("Email Validation")  # Also track in the database

elif tool == "🔎 MAC Address Lookup":
    st.subheader("🔎 MAC Address Lookup")
    st.write(
        """
    This tool provides information about a MAC address.

    **How it works:**

    1. **Input:** Enter the MAC address you want to look up in the text input field.
    2. **Lookup:** Click the "🔍 Lookup" button. The tool will fetch information about the MAC address.
    3. **Results:** The MAC address information will be displayed in a table.

    **What you'll get:**

    - **MAC Address:** The MAC address you entered.
    - **Vendor:** The vendor associated with the MAC address.
    """
    )

    mac_address = st.text_input(
        "Enter MAC address", placeholder="e.g., 00:1A:2B:3C:4D:5E"
    )
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up MAC address..."):
            mac_info = mac_address_lookup(mac_address)
        if "error" in mac_info:
            st.error(mac_info["error"])
        else:
            display_results(mac_info)

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["MAC Address Lookup"] = st.session_state.tool_usage.get("MAC Address Lookup",
                                                                                                0) + 1
            track_tool_usage("MAC Address Lookup")  # Also track in the database



elif tool == "🔏 SSL Certificate Check":
    st.subheader("🔏 SSL Certificate Check")
    st.write(
        """
    This tool checks the SSL certificate details for a given domain.

    **How it works:**

    1. **Input:** Enter the domain name you want to check for SSL certificate in the text input field.
    2. **Check:** Click the "🔍 Check" button. The tool will fetch the SSL certificate details.
    3. **Results:** The SSL certificate details will be displayed in a table.

    **What you'll get:**

    - **Issuer:** The issuer of the SSL certificate.
    - **Subject:** The subject of the SSL certificate.
    - **Valid From:** The start date of the certificate's validity.
    - **Valid To:** The end date of the certificate's validity.
    - **Serial Number:** The serial number of the certificate.
    """
    )

    domain_name = st.text_input("Enter domain name for SSL certificate check", placeholder="e.g., google.com")
    if st.button("🔍 Check"):
        with st.spinner("Checking SSL certificate..."):
            ssl_certificate_results = ssl_certificate_check(domain_name)
        if "error" in ssl_certificate_results:
            st.error(ssl_certificate_results["error"])
        else:
            display_results(ssl_certificate_results)

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["SSL Certificate Check"] = st.session_state.tool_usage.get(
                "SSL Certificate Check", 0) + 1
            track_tool_usage("SSL Certificate Check")  # Also track in the database


elif tool == "🌐 DNS Lookup":
    st.subheader("🌐 DNS Lookup")
    st.write(
        """
    This tool performs DNS lookups for a given domain.

    **How it works:**

    1. **Input:** Enter the domain name you want to look up in the text input field.
    2. **Lookup:** Click the "🔍 Lookup" button. The tool will fetch the DNS records.
    3. **Results:** The DNS lookup results will be displayed in a table.

    **What you'll get:**

    - **A Records:** The A records for the domain.
    """
    )

    domain_name_dns = st.text_input("Enter domain name for DNS lookup", placeholder="e.g., google.com")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up DNS..."):
            dns_results = dns_lookup(domain_name_dns)
        if "error" in dns_results:
            st.error(dns_results["error"])
        else:
            display_results(dns_results)

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["DNS Lookup"] = st.session_state.tool_usage.get("DNS Lookup", 0) + 1
            track_tool_usage("DNS Lookup")  # Also track in the database


elif tool == "🔍 WHOIS Lookup":
    st.subheader("🔍 WHOIS Lookup")
    st.write(
        """
    This tool retrieves WHOIS information for a given domain.

    **How it works:**

    1. **Input:** Enter the domain name you want to look up in the text input field.
    2. **Lookup:** Click the "🔍 Lookup" button. The tool will fetch the WHOIS records.
    3. **Results:** The WHOIS lookup results will be displayed in a table.

    **What you'll get:**

    - **Domain Name:** The domain name you entered.
    - **Registrar:** The registrar of the domain.
    - **Creation Date:** The date the domain was created.
    - **Expiration Date:** The date the domain will expire.
    - **Name Servers:** The name servers associated with the domain.
    """
    )

    domain_name_whois = st.text_input("Enter domain name for WHOIS lookup", placeholder="e.g., google.com")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up WHOIS..."):
            whois_results = whois_lookup(domain_name_whois)
        if "error" in whois_results:
            st.error(whois_results["error"])
        else:
            display_results(whois_results)

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["WHOIS Lookup"] = st.session_state.tool_usage.get("WHOIS Lookup", 0) + 1
            track_tool_usage("WHOIS Lookup")  # Also track in the database


elif tool == "🛡️ Malware URL Check":
    st.subheader("🛡️ Malware URL Check")
    st.write(
        """
    This tool checks a given URL for potential malware.

    **How it works:**

    1. **Input:** Enter the URL you want to check for malware in the text input field.
    2. **Check:** Click the "🔍 Check" button. The tool will perform a malware check.
    3. **Results:** The malware check results will be displayed in a table.

    **What you'll get:**

    - **URL:** The URL you entered.
    - **Malware Status:** The status of the URL regarding malware.
    """
    )

    url = st.text_input("Enter URL for malware check", placeholder="e.g., https://example.com")
    if st.button("🔍 Check"):
        with st.spinner("Checking malware URL..."):
            malware_results = malware_url_check(url)
        if "error" in malware_results:
            st.error(malware_results["error"])
        else:
            display_results(malware_results)

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["Malware URL Check"] = st.session_state.tool_usage.get("Malware URL Check",
                                                                                               0) + 1
            track_tool_usage("Malware URL Check")  # Also track in the database


elif tool == "📊 Website Statistics":
    st.subheader("📊 Website Statistics")
    st.write(
        """
    This tool retrieves website statistics for a given domain.

    **How it works:**

    1. **Input:** Enter the domain name you want to get statistics for in the text input field.
    2. **Get Stats:** Click the "🔍 Get Stats" button. The tool will fetch the website statistics.
    3. **Results:** The website statistics will be displayed in a table.

    **What you'll get:**

    - **Global Rank:** The global rank of the domain.
    - **Data Points Charged:** The number of data points charged for the request.

    **Note:** The free version of the SimilarWeb API has limited data. You may see 'N/A' for the Global Rank if data 
    is not available for the domain."""
    )

    domain_name_stats = st.text_input(
        "Enter domain name for website statistics", placeholder="e.g., google.com"
    )
    if st.button("🔍 Get Stats"):
        with st.spinner("Fetching website statistics..."):
            website_stats = website_statistics(domain_name_stats)

        if "error" in website_stats:
            st.error(website_stats["error"])
        else:
            display_results(website_stats)

            # Store tool usage in session state
            if 'tool_usage' not in st.session_state:
                st.session_state.tool_usage = {}

            st.session_state.tool_usage["Website Statistics"] = st.session_state.tool_usage.get("Website Statistics",
                                                                                                0) + 1
            track_tool_usage("Website Statistics")

# Footer
st.sidebar.markdown("---")
st.sidebar.markdown("### CyberGuard - Your Cybersecurity Companion")
st.sidebar.markdown("© 2024 CyberGuard. All rights reserved.")
st.sidebar.markdown("🔗 [Privacy Policy](#)")
st.sidebar.markdown("🔗 [Terms of Service](#)")
st.sidebar.markdown(
    "📧 Contact us: [support@cyberguard.com](mailto:support@cyberguard.com)"
)
st.sidebar.markdown(
    "Follow us on [Twitter](https://twitter.com/cyberguard) | [LinkedIn](https://linkedin.com/company/cyberguard)"
)
