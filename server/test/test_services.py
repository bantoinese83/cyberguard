import os
import unittest
from unittest.mock import patch, Mock

import requests
from dotenv import load_dotenv

from services import website_statistics

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


if __name__ == "__main__":
    unittest.main()
