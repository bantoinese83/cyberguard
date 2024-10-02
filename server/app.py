import socket

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

from services import ip_lookup, trace_email, security_check, speed_test, get_user_ip_info, phone_number_lookup, \
    proxy_check, reverse_dns_lookup, port_scan, ssl_certificate_check, dns_lookup, whois_lookup, malware_url_check, \
    mac_address_lookup, email_validation , website_statistics

# Load breach data

# Set page configuration
st.set_page_config(page_title="CyberGuard", layout="wide")

# Custom CSS for better styling
st.markdown("""
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
    """, unsafe_allow_html=True)

# Display logo and title
st.sidebar.image("cyberguard_logo.png", width=100)

st.title("CyberGuard")

user_ip_info = get_user_ip_info()

# Sidebar navigation
st.sidebar.title("🔍 Navigation")
if "error" not in user_ip_info:
    st.sidebar.write(f"**IP:** {user_ip_info['ip']}")
    st.sidebar.write(f"**Location:** {user_ip_info['city']}, {user_ip_info['region']}, {user_ip_info['country']}")

    # Display the location on a small map if latitude and longitude are available
    if "loc" in user_ip_info:
        lat, lon = map(float, user_ip_info["loc"].split(","))
        location_df = pd.DataFrame({
            'lat': [lat],
            'lon': [lon]
        })
        st.sidebar.map(location_df, zoom=10)
else:
    st.sidebar.write("Unable to fetch IP information")

tool = st.sidebar.radio("Go to",
                        ["🌐 IP Lookup", "📧 Email Trace", "🔒 Security Check", "📶 Internet Speed Test",
                         "📞 Phone Number Lookup", "🔍 Host Name to IP", "🔐 Proxy Check", "🔐 Reverse DNS Lookup",
                         "📧 Email Validation", "🔍 MAC Address Lookup", "🔐 Port Scan", "🔐 SSL Certificate Check",
                         "🔐 DNS Lookup", "🔐 WHOIS Lookup", "🔐 Malware URL Check", "📊 Website Statistics"])
st.header("🔐 IP and Email Security Tool")

if tool == "🌐 IP Lookup":
    st.subheader("🌐 IP Lookup")
    st.write("### Instructions")
    st.write("1. Enter the IP address you want to look up in the text input field.")
    st.write("2. Click the '🔍 Lookup' button.")
    st.write("3. View the IP information in the table and map (if available).")

    st.write("### How to Get Someone's IP Address")
    st.write(
        "If you don't know how to get someone's IP address, read: [11 Ways To Get Someone's IP Address]("
        "https://whatismyipaddress.com/get-ip).")
    st.write("If you want to get your own IP address, you can simply search 'What is my IP address?' on Google.")

    st.write("### What You Will Get with This Tool")
    st.write("With this tool, you will get detailed information about the IP address, including:")
    st.write("- 🌐 **IP Address**: The IP address you entered.")
    st.write("- 📍 **City**: The city where the IP address is located.")
    st.write("- 🏢 **Region**: The region where the IP address is located.")
    st.write("- 🌍 **Country**: The country where the IP address is located.")
    st.write("- 🏷️ **Postal Code**: The postal code of the IP address location.")
    st.write("- 🌐 **Latitude and Longitude**: The coordinates of the IP address location.")
    st.write("- 🕒 **Timezone**: The timezone of the IP address location.")
    st.write("- 🏢 **Organization**: The organization that owns the IP address.")
    st.write("- 🔢 **ASN (Autonomous System Number)**: The ASN associated with the IP address.")
    st.write("- 🌐 **ISP (Internet Service Provider)**: The ISP associated with the IP address.")
    st.write("- 🚫 **Blacklist Status**: Whether the IP address is blacklisted or not.")
    st.write("- 📶 **Download Speed**: The download speed for the IP address (if available).")
    st.write("- 📤 **Upload Speed**: The upload speed for the IP address (if available).")
    st.write("- 🏓 **Ping**: The ping time for the IP address (if available).")
    st.write("- 🌐 **Speed Test Server**: Details of the speed test server used (if available).")
    st.write("- 🕒 **Timestamp**: The timestamp of the speed test (if available).")
    st.write("- 📊 **Bytes Sent**: The number of bytes sent during the speed test (if available).")
    st.write("- 📥 **Bytes Received**: The number of bytes received during the speed test (if available).")
    st.write("- 🌐 **Client Info**: Information about the client performing the speed test (if available).")

    ip_address = st.text_input("Enter IP address")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up IP..."):
            ip_info = ip_lookup(ip_address)
            blacklist_info = security_check(ip_address)
            speed_info = speed_test()

        if "error" in ip_info:
            st.error(ip_info["error"])
        else:
            # Combine all information into a single dictionary
            combined_info = {**ip_info, **blacklist_info, **speed_info}
            # Convert the dictionary to a DataFrame for better display
            combined_info_df = pd.DataFrame(combined_info.items(), columns=["Key", "Value"])
            st.table(combined_info_df)

            # Display the location on a map if latitude and longitude are available
            if "lat" in ip_info and "lon" in ip_info:
                location_df = pd.DataFrame({
                    'lat': [float(ip_info['lat'])],
                    'lon': [float(ip_info['lon'])]
                })
                st.map(location_df)
            else:
                st.warning("Location data not available for this IP address.")

    # Monetization: Subscription Model
    st.sidebar.write("### Subscribe for Premium Features")
    st.sidebar.write("Get access to detailed IP lookup information, including blacklist status and speed test results.")
    if st.sidebar.button("Subscribe Now"):
        st.sidebar.markdown("[Proceed to Checkout](https://example.com/checkout)", unsafe_allow_html=True)

elif tool == "📧 Email Trace":
    st.subheader("📧 Email Trace")
    st.write("### Instructions")
    st.write("1. Find the email header in your email client. [Learn how to find email headers]("
             "https://mxtoolbox.com/Public/Content/EmailHeaders/).")
    st.write("2. Paste the email header into the text area provided.")
    st.write("3. Click the '🔍 Trace' button.")
    st.write("4. View the trace information in JSON format.")

    email_header = st.text_area("Enter email header", placeholder="Received: from mac.com ([10.13.11.252])\n  by "
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
                                                                  "Thu, 09 Aug 2007 04:24:49 -0700")
    if st.button("🔍 Trace"):
        with st.spinner("Tracing email..."):
            email_trace = trace_email(email_header)
        if "error" in email_trace:
            st.error(email_trace["error"])
        else:
            st.json(email_trace)

elif tool == "🔒 Security Check":
    st.subheader("🔒 Security Check")
    st.write("### Instructions")
    st.write("1. Enter the IP address you want to check for security in the text input field.")
    st.write("2. Click the '🔍 Check' button.")
    st.write("3. View the security status in JSON format.")

    ip_address_check = st.text_input("Enter IP address for security check")
    if st.button("🔍 Check"):
        with st.spinner("Checking security..."):
            security_status = security_check(ip_address_check)
        if "error" in security_status:
            st.error(security_status["error"])
        else:
            st.json(security_status)

elif tool == "📶 Internet Speed Test":
    st.subheader("📶 Internet Speed Test")
    st.write("### Instructions")
    st.write("1. Click the '🏃‍♂️ Run Test' button to start the speed test.")
    st.write("2. View the speed test results, including download speed, upload speed, and ping.")
    st.write("3. View server and client information, gauge charts, and server location on a map.")

    if st.button("🏃‍♂️ Run Test"):
        with st.spinner("Running speed test..."):
            speedtest_results = speed_test()
        if "error" in speedtest_results:
            st.error(speedtest_results["error"])
        else:
            st.subheader("📊 Speed Test Results")

            # Display key metrics
            col1, col2, col3 = st.columns(3)
            col1.metric(label="Download Speed", value=f"{speedtest_results['download'] / 1_000_000:.2f} Mbps")
            col2.metric(label="Upload Speed", value=f"{speedtest_results['upload'] / 1_000_000:.2f} Mbps")
            col3.metric(label="Ping", value=f"{speedtest_results['ping']} ms")

            # Display server information
            st.write("### Server Information")
            server_info = speedtest_results['server']
            st.write(f"Server: {server_info['name']}, {server_info['country']} ({server_info['sponsor']})")
            st.write(f"Server Latency: {server_info['latency']} ms")

            # Display client information
            st.write("### Client Information")
            client_info = speedtest_results['client']
            st.write(f"Client IP: {client_info['ip']}")
            st.write(f"Client ISP: {client_info['isp']}")
            st.write(f"Client Country: {client_info['country']}")
            st.write(f"Client Location: {client_info['lat']}, {client_info['lon']}")

            # Create a gauge chart for download speed
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=speedtest_results['download'] / 1_000_000,
                title={'text': "Download Speed (Mbps)"},
                gauge={'axis': {'range': [None, 1000]}}
            ))
            st.plotly_chart(fig)

            # Create a gauge chart for upload speed
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=speedtest_results['upload'] / 1_000_000,
                title={'text': "Upload Speed (Mbps)"},
                gauge={'axis': {'range': [None, 1000]}}
            ))
            st.plotly_chart(fig)

            # Create a gauge chart for ping
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=speedtest_results['ping'],
                title={'text': "Ping (ms)"},
                gauge={'axis': {'range': [None, 100]}}
            ))
            st.plotly_chart(fig)

            # Display server location on a map
            server_location = pd.DataFrame({
                'lat': [float(server_info['lat'])],
                'lon': [float(server_info['lon'])]
            })
            st.map(server_location)

elif tool == "📞 Phone Number Lookup":
    st.subheader("📞 Phone Number Lookup")
    st.write("### Instructions")
    st.write("1. Enter the phone number you want to look up in the text input field.")
    st.write("2. Click the '🔍 Lookup' button.")
    st.write("3. View the phone number information in the table and map (if available).")

    phone_number = st.text_input("Enter phone number")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up phone number..."):
            phone_info = phone_number_lookup(phone_number)
        if "error" in phone_info:
            st.error(phone_info["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            phone_info_df = pd.DataFrame(phone_info.items(), columns=["Key", "Value"])
            st.table(phone_info_df)

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
                    if geocode_data and geocode_data['results']:
                        lat = geocode_data['results'][0]['geometry']['lat']
                        lon = geocode_data['results'][0]['geometry']['lng']
                        location_df = pd.DataFrame({
                            'lat': [lat],
                            'lon': [lon]
                        })
                        st.map(location_df)
                    else:
                        st.warning("Geocoding service did not return any results.")
                except requests.RequestException as e:
                    st.error(f"Error fetching geocoding data: {e}")

elif tool == "🔍 Host Name to IP":
    st.subheader("🔍 Host Name to IP")
    st.write("### Instructions")
    st.write("1. Enter the host name you want to look up in the text input field.")
    st.write("2. Click the '🔍 Lookup' button.")
    st.write("3. View the IP address information in the table.")

    host_name = st.text_input("Enter host name")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up host name..."):
            try:
                host_ip = socket.gethostbyname(host_name)
                host_ip_info = {"host_name": host_name, "ip_address": host_ip}
                # Convert the dictionary to a DataFrame for better display
                host_ip_df = pd.DataFrame(host_ip_info.items(), columns=["Key", "Value"])
                st.table(host_ip_df)
            except socket.gaierror as e:
                st.error(f"Error looking up host name: {e}")

elif tool == "🔐 Proxy Check":
    st.subheader("🔐 Proxy Check")
    st.write("### Instructions")
    st.write("1. Enter the IP address you want to check for proxy in the text input field.")
    st.write("2. Click the '🔍 Check' button.")
    st.write("3. View the proxy check results in the table.")

    ip_address_proxy = st.text_input("Enter IP address for proxy check")
    if st.button("🔍 Check"):
        with st.spinner("Checking proxy..."):
            proxy_results = proxy_check(ip_address_proxy)
        if "error" in proxy_results:
            st.error(proxy_results["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            proxy_results_df = pd.DataFrame(proxy_results.items(), columns=["Key", "Value"])
            st.table(proxy_results_df)

elif tool == "🔐 Reverse DNS Lookup":
    st.subheader("🔐 Reverse DNS Lookup")
    st.write("### Instructions")
    st.write("1. Enter the IP address you want to look up in the text input field.")
    st.write("2. Click the '🔍 Lookup' button.")
    st.write("3. View the reverse DNS lookup results in the table.")

    ip_address_reverse_dns = st.text_input("Enter IP address for reverse DNS lookup")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up reverse DNS..."):
            reverse_dns_results = reverse_dns_lookup(ip_address_reverse_dns)
        if "error" in reverse_dns_results:
            st.error(reverse_dns_results["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            reverse_dns_results_df = pd.DataFrame(reverse_dns_results.items(), columns=["Key", "Value"])
            st.table(reverse_dns_results_df)

elif tool == "📧 Email Validation":
    st.subheader("📧 Email Validation")
    st.write("### Instructions")
    st.write("1. Enter the email address you want to validate in the text input field.")
    st.write("2. Click the '🔍 Validate' button.")
    st.write("3. View the validation results in the table.")

    email = st.text_input("Enter email address")
    if st.button("🔍 Validate"):
        with st.spinner("Validating email..."):
            email_validation_result = email_validation(email)
        if "error" in email_validation_result:
            st.error(email_validation_result["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            email_validation_df = pd.DataFrame(email_validation_result.items(), columns=["Key", "Value"])
            st.table(email_validation_df)

elif tool == "🔍 MAC Address Lookup":
    st.subheader("🔍 MAC Address Lookup")
    st.write("### Instructions")
    st.write("1. Enter the MAC address you want to look up in the text input field.")
    st.write("2. Click the '🔍 Lookup' button.")
    st.write("3. View the MAC address information in the table.")

    mac_address = st.text_input("Enter MAC address", placeholder="e.g., 00:1A:2B:3C:4D:5E")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up MAC address..."):
            mac_info = mac_address_lookup(mac_address)
        if "error" in mac_info:
            st.error(mac_info["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            mac_info_df = pd.DataFrame(mac_info.items(), columns=["Key", "Value"])
            mac_info_df["Value"] = mac_info_df["Value"].astype(str)  # Ensure all values are strings
            st.table(mac_info_df)

elif tool == "🔐 Port Scan":
    st.subheader("🔐 Port Scan")
    st.write("### Instructions")
    st.write("1. Enter the IP address you want to scan in the text input field.")
    st.write("2. Click the '🔍 Scan' button.")
    st.write("3. View the port scan results in the table.")

    ip_address_port_scan = st.text_input("Enter IP address for port scan")
    if st.button("🔍 Scan"):
        with st.spinner("Scanning ports..."):
            port_scan_results = port_scan(ip_address_port_scan)
        if "error" in port_scan_results:
            st.error(port_scan_results["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            port_scan_results_df = pd.DataFrame(port_scan_results.items(), columns=["Key", "Value"])
            st.table(port_scan_results_df)

elif tool == "🔐 SSL Certificate Check":
    st.subheader("🔐 SSL Certificate Check")
    st.write("### Instructions")
    st.write("1. Enter the domain name you want to check for SSL certificate in the text input field.")
    st.write("2. Click the '🔍 Check' button.")
    st.write("3. View the SSL certificate details in the table.")

    domain_name = st.text_input("Enter domain name for SSL certificate check")
    if st.button("🔍 Check"):
        with st.spinner("Checking SSL certificate..."):
            ssl_certificate_results = ssl_certificate_check(domain_name)
        if "error" in ssl_certificate_results:
            st.error(ssl_certificate_results["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            ssl_certificate_results_df = pd.DataFrame(ssl_certificate_results.items(), columns=["Key", "Value"])
            st.table(ssl_certificate_results_df)

elif tool == "🔐 DNS Lookup":
    st.subheader("🔐 DNS Lookup")
    st.write("### Instructions")
    st.write("1. Enter the domain name you want to look up in the text input field.")
    st.write("2. Click the '🔍 Lookup' button.")
    st.write("3. View the DNS lookup results in the table.")

    domain_name_dns = st.text_input("Enter domain name for DNS lookup")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up DNS..."):
            dns_results = dns_lookup(domain_name_dns)
        if "error" in dns_results:
            st.error(dns_results["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            dns_results_df = pd.DataFrame(dns_results.items(), columns=["Key", "Value"])
            st.table(dns_results_df)

elif tool == "🔐 WHOIS Lookup":
    st.subheader("🔐 WHOIS Lookup")
    st.write("### Instructions")
    st.write("1. Enter the domain name you want to look up in the text input field.")
    st.write("2. Click the '🔍 Lookup' button.")
    st.write("3. View the WHOIS lookup results in the table.")

    domain_name_whois = st.text_input("Enter domain name for WHOIS lookup")
    if st.button("🔍 Lookup"):
        with st.spinner("Looking up WHOIS..."):
            whois_results = whois_lookup(domain_name_whois)
        if "error" in whois_results:
            st.error(whois_results["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            whois_results_df = pd.DataFrame(whois_results.items(), columns=["Key", "Value"])
            whois_results_df["Value"] = whois_results_df["Value"].astype(str)  # Ensure all values are strings
            st.table(whois_results_df)

elif tool == "🔐 Malware URL Check":
    st.subheader("🔐 Malware URL Check")
    st.write("### Instructions")
    st.write("1. Enter the URL you want to check for malware in the text input field.")
    st.write("2. Click the '🔍 Check' button.")
    st.write("3. View the malware check results in the table.")

    url = st.text_input("Enter URL for malware check")
    if st.button("🔍 Check"):
        with st.spinner("Checking malware URL..."):
            malware_results = malware_url_check(url)
        if "error" in malware_results:
            st.error(malware_results["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            malware_results_df = pd.DataFrame(malware_results.items(), columns=["Key", "Value"])
            st.table(malware_results_df)


elif tool == "📊 Website Statistics":
    st.subheader("📊 Website Statistics")
    st.write("### Instructions")
    st.write("1. Enter the domain name you want to get statistics for in the text input field.")
    st.write("2. Click the '🔍 Get Stats' button.")
    st.write("3. View the website statistics in the table.")

    # Add example placeholder text
    domain_name_stats = st.text_input("Enter domain name for website statistics", placeholder="e.g., example.com")
    if st.button("🔍 Get Stats"):
        with st.spinner("Fetching website statistics..."):
            website_stats = website_statistics(domain_name_stats)
        if "error" in website_stats:
            st.error(website_stats["error"])
        else:
            # Convert the dictionary to a DataFrame for better display
            website_stats_df = pd.DataFrame(website_stats.items(), columns=["Key", "Value"])
            st.table(website_stats_df)

# Footer
st.sidebar.markdown("---")
st.sidebar.write("Made with ❤️ by [CyberGuard](basedev83@gmail.com)")





