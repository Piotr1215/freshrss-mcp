import unittest
from unittest.mock import patch, MagicMock
from freshrss_mcp_server import mark_article_read

class TestMarkArticleRead(unittest.TestCase):
    @patch('freshrss_mcp_server._api_request')
    def test_mark_article_read_success(self, mock_api_request):
        # Mock the API request to return a success response
        mock_api_request.return_value = {"success": True, "message": "Article marked as read"}
        
        # Test successful marking of an article
        result = mark_article_read("12345")
        self.assertEqual(result, {"success": True, "message": "Article 12345 marked as read"})
    
    @patch('freshrss_mcp_server._api_request')
    def test_mark_article_read_error(self, mock_api_request):
        # Mock the API request to return an error response
        mock_api_request.return_value = {"error": "Invalid article ID"}
        
        # Test error case with invalid article ID
        result = mark_article_read("invalid_id")
        self.assertEqual(result, {"error": "Invalid article ID"})

if __name__ == "__main__":
    unittest.main()
