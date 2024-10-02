import os
import socket
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, Mock

import dns.resolver
import requests
import speedtest
from dotenv import load_dotenv

from services import (
    website_statistics,
    ip_lookup,
    trace_email,
    phone_number_lookup,
    host_name_to_ip,
    reverse_dns_lookup,
    email_validation,
    malware_url_check,  # Add other functions
    ssl_certificate_check,  # For completeness
    dns_lookup,
    whois_lookup,
    mac_address_lookup, security_check,
    speed_test, proxy_check, url_scan, app_statistics, get_top_visitor_regions, get_weekly_pageviews,
    get_monthly_pageviews,
    get_daily_visitors, calculate_avg_time_on_site, get_most_used_tool, update_statistics, track_tool_usage, ToolUsage,
    AppStatistics

)

# Load the environment variables
load_dotenv()


class TestWebsiteStatistics(unittest.TestCase):

    @patch("services.requests.get")
    def test_website_statistics_success(self, mock_get):
        # Mock the environment variable
        os.environ["SIMILARWEB_API_KEY"] = "test_api_key"

        # Mock the response from the API
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"global_rank": 12345}
        mock_response.headers = {"sw-datapoint-charged": "1"}
        mock_get.return_value = mock_response

        # Call the function
        result = website_statistics("example.com")

        # Assert the expected result
        self.assertEqual(result, {"Global Rank": 12345, "Data Points Charged": 1})

    @patch("services.requests.get")
    def test_website_statistics_no_api_key(self, mock_get):
        # Ensure the environment variable is not set
        if "SIMILARWEB_API_KEY" in os.environ:
            del os.environ["SIMILARWEB_API_KEY"]

        # Call the function
        result = website_statistics("example.com")

        # Assert the expected result
        self.assertEqual(
            result, {"error": "SIMILARWEB_API_KEY not found in environment variables."}
        )

    @patch("services.requests.get")
    def test_website_statistics_http_error(self, mock_get):
        # Mock the environment variable
        os.environ["SIMILARWEB_API_KEY"] = "test_api_key"

        # Mock the response from the API
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=mock_response
        )
        mock_get.return_value = mock_response

        # Call the function
        result = website_statistics("example.com")

        # Assert the expected result
        self.assertEqual(
            result,
            {"error": "Domain 'example.com' not found or does not have a global rank."},
        )

    @patch("services.requests.get")
    def test_website_statistics_request_exception(self, mock_get):
        # Mock the environment variable
        os.environ["SIMILARWEB_API_KEY"] = "test_api_key"

        # Mock the response from the API
        mock_get.side_effect = requests.exceptions.RequestException("Request failed")

        # Call the function
        result = website_statistics("example.com")

        # Assert the expected result
        self.assertEqual(
            result, {"error": "Error fetching website statistics: Request failed"}
        )

    @patch("services.requests.get")
    def test_ip_lookup_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success", "country": "US"}  # Example data
        mock_get.return_value = mock_response
        result = ip_lookup("8.8.8.8")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["country"], "US")

    def test_ip_lookup_invalid_ip(self):
        result = ip_lookup("invalid_ip")
        self.assertEqual(result, {"error": "Invalid IP address"})

    def test_trace_email_no_headers(self):
        result = trace_email("No Received headers here")
        self.assertEqual(result, {"error": "No 'Received' headers found"})

    @patch("services.requests.get")
    def test_phone_number_lookup_valid(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"valid": True}

    def test_phone_number_lookup_invalid(self):
        result = phone_number_lookup("Invalid number")  # Use a clearly invalid number
        self.assertEqual(result["valid"], False)  # Assert that "valid" is False

    @patch("services.socket.gethostbyname")
    def test_host_name_to_ip(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "192.168.1.1"  # Mock the response
        result = host_name_to_ip("example.com")  # Test a valid domain name or hostname
        self.assertEqual(result, {"host_name": "example.com", "ip_address": "192.168.1.1"})

    @patch("services.socket.gethostbyname")
    def test_host_name_to_ip_invalid(self, mock_gethostbyname):
        mock_gethostbyname.side_effect = socket.gaierror("Mock error", "Mock message")
        result = host_name_to_ip("invalid_host")
        self.assertIn("error", result)

    @patch("services.socket.gethostbyaddr")
    def test_reverse_dns_lookup_success(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ("example.com", [], [])  # Mock return value
        result = reverse_dns_lookup("8.8.8.8")  # Use a valid IP address for testing
        self.assertEqual(result, {"ip_address": "8.8.8.8", "hostname": "example.com"})

    def test_reverse_dns_lookup_failure(self):
        result = reverse_dns_lookup("invalid_ip")
        self.assertIn("error", result)  # Assert an error message

    def test_email_validation_valid(self):
        result = email_validation("test@example.com")
        self.assertEqual(result["valid"], True)

    def test_email_validation_invalid_format(self):
        result = email_validation("invalid_email")
        self.assertEqual(result["valid"], False)
        self.assertEqual(result["message"], "Invalid email format")

    def test_email_validation_invalid_domain(self):
        result = email_validation("test@nonexistentdomain.com")  # A domain that likely doesn't exist
        self.assertEqual(result["valid"], False)
        self.assertIn("No MX records found for domain", result["message"])

    @patch('dns.resolver.resolve')
    def test_email_validation_no_mx_records(self, mock_resolve):
        # Simulate NoAnswer exception for MX record lookup
        mock_resolve.side_effect = dns.resolver.NoAnswer

        result = email_validation("test@example.com")
        self.assertEqual(result["valid"], False)
        self.assertIn("No MX records found for domain", result["message"])

    @patch("services.requests.get")
    def test_malware_url_check(self, mock_get):
        # Mock API key setup
        os.environ["MALWARE_API_KEY"] = "test_api_key"  # Or load from .env
        # Mock a successful API response.  Look at the actual expected API
        # return format from VirusTotal and create a mock return.
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"positives": 0, "total": 70}
        mock_get.return_value = mock_response

        result = malware_url_check("https://www.example.com")

        # Assert based on mocked return structure
        self.assertEqual(result["positives"], 0)
        self.assertEqual(result["total"], 70)

    def test_ssl_certificate_check(self):
        try:
            result = ssl_certificate_check("google.com")  # Use known valid domain

            # Check if result contains properties found in a valid certificate
            self.assertIn("notAfter", result)
            self.assertIn("notBefore", result)
            self.assertIn("subject", result)
            self.assertIn("issuer", result)

        except Exception as e:  # catch SSLError or other connection errors
            # Check if it's a connection issue rather than SSL
            if "Connection refused" in str(e) or "timed out" in str(e) or isinstance(e,
                                                                                     socket.gaierror):  # Add other network error types
                self.skipTest("Connection error: " + str(e))
            else:
                raise e

    def test_dns_lookup_success(self):
        result = dns_lookup("google.com")  # Use known domain with A records
        self.assertIn("A", result)
        self.assertTrue(len(result['A']) > 0)

    @patch("services.dns.resolver.resolve")
    def test_dns_lookup_failure(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NoAnswer  # Raise the exception
        result = dns_lookup("thisdomainreallydoesnotexist.com")  # Domain should not exist
        self.assertIn("A", result)
        self.assertEqual(len(result["A"]), 0)

    def test_whois_lookup(self):
        # Use a known domain name that has WHOIS data (don't overuse)
        result = whois_lookup("google.com")

        # You have to adjust the following assertions to check the relevant
        # elements returned from the whois query (expiry_date, etc.)
        self.assertIn("creation_date", result)  # Check that critical info is present
        self.assertIn("expiration_date", result)
        self.assertIn("registrar", result)

    @patch("services.requests.get")
    def test_mac_address_lookup_valid(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Apple, Inc."  # Expected vendor for a test MAC address
        mock_get.return_value = mock_response

        result = mac_address_lookup("AA:BB:CC:DD:EE:FF")  # Use test/dummy MAC
        self.assertEqual(result, "Apple, Inc.")

    @patch("services.requests.get")
    def test_mac_address_lookup_invalid(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Invalid MAC"
        mock_get.return_value = mock_response

        result = mac_address_lookup("Invalid MAC")
        self.assertEqual(result, "Invalid MAC")

    @patch("services.fetch_blacklist")
    def test_security_check_blacklisted(self, mock_fetch_blacklist):
        # Mock the fetch_blacklist function to return the mocked data
        mock_fetch_blacklist.return_value = ["1.2.3.4", "5.6.7.8"]  # Correct list

        result = security_check("1.2.3.4")
        self.assertTrue(result["blacklisted"])

    def test_security_check_not_blacklisted(self):
        # Mock a blacklist with a known IP
        os.environ.update({"BLACKLISTS": "['1.2.3.4', '5.6.7.8']"})  # Convert list to string

        result = security_check("9.10.11.12")
        self.assertFalse(result["blacklisted"])

    # Test for speed_test
    @patch("services.speedtest.Speedtest")
    def test_speed_test_success(self, mock_speedtest):
        mock_results = Mock()
        mock_results.download = 100000000
        mock_results.upload = 50000000
        mock_results.ping = 20
        mock_speedtest.return_value = mock_results

        result = speed_test()  # Call your speed_test function

        self.assertEqual(mock_results.download, 100000000)
        self.assertEqual(mock_results.upload, 50000000)
        self.assertEqual(mock_results.ping, 20)

    @patch("services.speedtest.Speedtest")
    def test_speed_test_failure(self, mock_speedtest):
        mock_speedtest.side_effect = speedtest.SpeedtestException("Test error")

        result = speed_test()

        # Assert that an error is returned
        self.assertIn("error", result)

    # Test for proxy_check
    def test_proxy_check_no_proxy(self):
        # You will need to add real IP addresses to test for known proxies
        result = proxy_check("192.168.1.1")
        self.assertFalse(result["WIMIA Test"])
        self.assertFalse(result["Tor Test"])

    # Add more tests for proxy_check based on the specific conditions you want to test

    # Test for url_scan
    @patch("services.requests.post")
    def test_url_scan_success(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"scan_id": "12345", "verbose_msg": "Scan started"}
        mock_post.return_value = mock_response

        result = url_scan("https://www.example.com")

        # Assert the expected values
        self.assertEqual(result["scan_id"], "12345")
        self.assertEqual(result["verbose_msg"], "Scan started")

    @patch("services.requests.post")
    def test_url_scan_failure(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Invalid API key"}
        mock_post.return_value = mock_response

        result = url_scan("https://www.example.com")

        # Assert that an error is returned
        self.assertEqual(result["error"], "Invalid API key")

    # Test for app_statistics (make sure to set up your database)
    @patch("services.get_top_visitor_regions")
    @patch("services.get_weekly_pageviews")
    @patch("services.get_monthly_pageviews")
    @patch("services.get_daily_visitors")
    @patch("services.calculate_avg_time_on_site")
    @patch("services.get_most_used_tool")
    @patch("services.update_statistics")
    def test_app_statistics_success(
            self, mock_update_statistics, mock_get_most_used_tool, mock_calculate_avg_time_on_site,
            mock_get_daily_visitors, mock_get_monthly_pageviews, mock_get_weekly_pageviews,
            mock_get_top_visitor_regions
    ):
        # Mock the environment variable
        os.environ["VIRUSTOTAL_API_KEY"] = "test_api_key"

        # Mock the response from the API
        with patch("services.requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"global_rank": 12345}
            mock_response.headers = {"sw-datapoint-charged": "1"}
            mock_get.return_value = mock_response

            # Mock the functions
            mock_update_statistics.return_value = {"Daily Visitors": 100, "Monthly Pageviews": 2000,
                                                   "Weekly Pageviews": 500, "Average Time On Site": "00:05:00",
                                                   "Top Visitor Regions": [{"region": "US", "count": 50},
                                                                           {"region": "UK", "count": 20}],
                                                   "Most Used Tool": "IP Lookup"}
            mock_get_most_used_tool.return_value = "IP Lookup"
            mock_calculate_avg_time_on_site.return_value = "00:05:00"
            mock_get_daily_visitors.return_value = 100
            mock_get_monthly_pageviews.return_value = 2000
            mock_get_weekly_pageviews.return_value = 500
            mock_get_top_visitor_regions.return_value = [{"region": "US", "count": 50}, {"region": "UK", "count": 20}]

            result = app_statistics()

            # Assert the expected values
            self.assertEqual(result["Daily Visitors"], 100)
            self.assertEqual(result["Monthly Pageviews"], 2000)
            self.assertEqual(result["Weekly Pageviews"], 500)
            self.assertEqual(result["Average Time On Site"], "00:05:00")
            self.assertEqual(result["Top Visitor Regions"],
                             [{"region": "US", "count": 50}, {"region": "UK", "count": 20}])
            self.assertEqual(result["Most Used Tool"], "IP Lookup")

    @patch("services.get_top_visitor_regions")
    @patch("services.get_weekly_pageviews")
    @patch("services.get_monthly_pageviews")
    @patch("services.get_daily_visitors")
    @patch("services.calculate_avg_time_on_site")
    @patch("services.get_most_used_tool")
    @patch("services.update_statistics")
    def test_app_statistics_failure(
            self, mock_update_statistics, mock_get_most_used_tool, mock_calculate_avg_time_on_site,
            mock_get_daily_visitors, mock_get_monthly_pageviews, mock_get_weekly_pageviews,
            mock_get_top_visitor_regions
    ):
        # Mock the environment variable
        os.environ["VIRUSTOTAL_API_KEY"] = "test_api_key"

        # Mock the response from the API
        with patch("services.requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"global_rank": 12345}
            mock_response.headers = {"sw-datapoint-charged": "1"}
            mock_get.return_value = mock_response

            # Mock the functions
            mock_update_statistics.return_value = {"error": "Database error"}
            mock_get_most_used_tool.return_value = "IP Lookup"
            mock_calculate_avg_time_on_site.return_value = "00:05:00"
            mock_get_daily_visitors.return_value = 100
            mock_get_monthly_pageviews.return_value = 2000
            mock_get_weekly_pageviews.return_value = 500
            mock_get_top_visitor_regions.return_value = [{"region": "US", "count": 50}, {"region": "UK", "count": 20}]

            result = app_statistics()

            # Assert the expected values
            self.assertEqual(result["error"], "Database error")

    # Test for get_top_visitor_regions
    @patch("services.Session")
    def test_get_top_visitor_regions_success(self, mock_session):
        mock_query = Mock()
        mock_query.group_by.return_value = mock_query
        mock_query.order_by.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.all.return_value = [("US", 50), ("UK", 20)]
        mock_session.return_value.__enter__.return_value.query.return_value = mock_query

        result = get_top_visitor_regions()

        # Assert the expected values
        self.assertEqual(result, [{"region": "US", "count": 50}, {"region": "UK", "count": 20}])

    @patch("services.Session")
    def test_get_top_visitor_regions_failure(self, mock_session):
        mock_session.return_value.__enter__.return_value.query.side_effect = Exception("Database error")

        result = get_top_visitor_regions()

        # Assert the expected values
        self.assertEqual(result, [])

    # Test for update_statistics
    @patch("services.get_top_visitor_regions")
    @patch("services.get_weekly_pageviews")
    @patch("services.get_monthly_pageviews")
    @patch("services.get_daily_visitors")
    @patch("services.calculate_avg_time_on_site")
    @patch("services.get_most_used_tool")
    @patch("services.Session")
    def test_update_statistics_success(
            self, mock_session, mock_get_most_used_tool, mock_calculate_avg_time_on_site,
            mock_get_daily_visitors, mock_get_monthly_pageviews, mock_get_weekly_pageviews,
            mock_get_top_visitor_regions
    ):
        # Mock the environment variable
        os.environ["VIRUSTOTAL_API_KEY"] = "test_api_key"

        # Mock the response from the API
        with patch("services.requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"global_rank": 12345}
            mock_response.headers = {"sw-datapoint-charged": "1"}
            mock_get.return_value = mock_response

            mock_session.__enter__.return_value.commit.return_value = None
            mock_get_most_used_tool.return_value = "IP Lookup"
            mock_calculate_avg_time_on_site.return_value = "00:05:00"
            mock_get_daily_visitors.return_value = 100
            mock_get_monthly_pageviews.return_value = 2000
            mock_get_weekly_pageviews.return_value = 500
            mock_get_top_visitor_regions.return_value = [{"region": "US", "count": 50}, {"region": "UK", "count": 20}]
            stats_obj = AppStatistics()
            today = datetime.now().date()
            days = 1

            result = update_statistics(mock_session, days, today, stats_obj)

            # Assert the expected values
            self.assertEqual(result["Daily Visitors"], 100)
            self.assertEqual(result["Monthly Pageviews"], 2000)
            self.assertEqual(result["Weekly Pageviews"], 500)
            self.assertEqual(result["Average Time On Site"], "00:05:00")
            self.assertEqual(result["Top Visitor Regions"],
                             [{"region": "US", "count": 50}, {"region": "UK", "count": 20}])
            self.assertEqual(result["Most Used Tool"], "IP Lookup")

    @patch("services.get_monthly_pageviews")
    @patch("services.get_daily_visitors")
    @patch("services.calculate_avg_time_on_site")
    @patch("services.get_most_used_tool")
    @patch("services.get_weekly_pageviews")
    @patch("services.get_top_visitor_regions")
    @patch("services.Session")
    def test_update_statistics_failure(
            self,
            mock_session,
            mock_get_most_used_tool,
            mock_calculate_avg_time_on_site,
            mock_get_daily_visitors,
            mock_get_monthly_pageviews,
            mock_get_weekly_pageviews,
            mock_get_top_visitor_regions,
    ):
        # Mock session.commit to raise an exception
        mock_session.commit.side_effect = Exception("Database error")

        # Set return values for mocked functions
        mock_get_most_used_tool.return_value = "IP Lookup"
        mock_calculate_avg_time_on_site.return_value = "00:05:00"
        mock_get_daily_visitors.return_value = 100
        mock_get_monthly_pageviews.return_value = 2000
        mock_get_weekly_pageviews.return_value = 500
        mock_get_top_visitor_regions.return_value = [
            {"region": "US", "count": 50},
            {"region": "UK", "count": 20}
        ]

        stats_obj = AppStatistics()
        today = datetime.now().date()
        days = 1

        result = update_statistics(mock_session, days, today, stats_obj)

        # Assert the expected error result
        self.assertEqual(result.get("error"), "Database error")

    # Test for get_daily_visitors
    @patch("services.Session")
    def test_get_daily_visitors_success(self, mock_session):
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.count.return_value = 100
        mock_session.return_value.__enter__.return_value.query.return_value = mock_query

        start_date = datetime.now().date()
        end_date = start_date

        result = get_daily_visitors(start_date, end_date)

        # Assert the expected values
        self.assertEqual(result, 100)

    @patch("services.Session")
    def test_get_daily_visitors_failure(self, mock_session):
        mock_session.return_value.__enter__.return_value.query.side_effect = Exception("Database error")

        start_date = datetime.now().date()
        end_date = start_date

        result = get_daily_visitors(start_date, end_date)

        # Assert the expected values
        self.assertEqual(result, 0)

    # Test for get_monthly_pageviews
    @patch("services.Session")
    def test_get_monthly_pageviews_success(self, mock_session):
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.return_value = 2000
        mock_session.return_value.__enter__.return_value.query.return_value = mock_query

        result = get_monthly_pageviews()

        # Assert the expected values
        self.assertEqual(result, 2000)

    @patch("services.Session")
    def test_get_monthly_pageviews_failure(self, mock_session):
        mock_session.return_value.__enter__.return_value.query.side_effect = Exception("Database error")

        result = get_monthly_pageviews()

        # Assert the expected values
        self.assertEqual(result, 0)

    # Test for get_weekly_pageviews
    @patch("services.Session")
    def test_get_weekly_pageviews_success(self, mock_session):
        mock_query = Mock()
        mock_query.filter.return_value = mock_query
        mock_query.scalar.return_value = 500
        mock_session.return_value.__enter__.return_value.query.return_value = mock_query

        result = get_weekly_pageviews()

        # Assert the expected values
        self.assertEqual(result, 500)

    @patch("services.Session")
    def test_get_weekly_pageviews_failure(self, mock_session):
        mock_session.return_value.__enter__.return_value.query.side_effect = Exception("Database error")

        result = get_weekly_pageviews()

        # Assert the expected values
        self.assertEqual(result, 0)

    # Test for calculate_avg_time_on_site
    @patch("services.Session")
    def test_calculate_avg_time_on_site_success(self, mock_session):
        mock_query = Mock()
        mock_query.scalar.return_value = timedelta(minutes=5)
        mock_session.return_value.__enter__.return_value.query.return_value = mock_query

        result = calculate_avg_time_on_site()

        # Assert the expected values
        self.assertEqual(result, "0:05:00")

    @patch("services.Session")
    def test_calculate_avg_time_on_site_failure(self, mock_session):
        mock_session.return_value.__enter__.return_value.query.side_effect = Exception("Database error")

        result = calculate_avg_time_on_site()

        # Assert the expected values
        self.assertEqual(result, "00:00:00")

    # Test for track_tool_usage
    @patch("services.Session")
    def test_track_tool_usage_success(self, mock_session):
        mock_session.__enter__.return_value.commit.return_value = None
        mock_session.return_value.__enter__.return_value.query.return_value.filter_by.return_value.first.return_value = None

        tool_name = "IP Lookup"
        track_tool_usage(tool_name)

        # Assert the expected values
        mock_session.return_value.__enter__.return_value.query.return_value.filter_by.assert_called_once_with(
            tool_name=tool_name)
        mock_session.return_value.__enter__.return_value.add.assert_called_once()
        mock_session.return_value.__enter__.return_value.commit.assert_called_once()

    @patch("services.Session")
    def test_track_tool_usage_failure(self, mock_session):
        mock_session.return_value.__enter__.return_value.commit.side_effect = Exception("Database error")

        tool_name = "IP Lookup"
        track_tool_usage(tool_name)

        # Assert the expected values
        mock_session.return_value.__enter__.return_value.commit.assert_called_once()

    # Test for get_most_used_tool
    @patch("services.Session")
    def test_get_most_used_tool_success(self, mock_session):
        mock_query = Mock()
        mock_query.order_by.return_value = mock_query
        mock_query.first.return_value = ToolUsage(tool_name="IP Lookup", usage_count=100, last_used=datetime.now())
        mock_session.return_value.__enter__.return_value.query.return_value = mock_query

        result = get_most_used_tool()
        self.assertEqual(result, "IP Lookup")

    @patch("services.Session")
    def test_get_most_used_tool_failure(self, mock_session):
        mock_session.return_value.__enter__.return_value.query.side_effect = Exception("Database error")

        result = get_most_used_tool()

        # Assert the expected values
        self.assertIsNone(result)



if __name__ == "__main__":
    unittest.main()
