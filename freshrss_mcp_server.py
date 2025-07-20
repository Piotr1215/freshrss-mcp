#!/usr/bin/env python3
"""
FreshRSS MCP Server

A Model Context Protocol server for interacting with FreshRSS via its Google Reader compatible API.
Provides tools for authentication, browsing feeds, reading articles, and managing subscriptions.
"""

import asyncio
import aiohttp
import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode, urljoin
from datetime import datetime
from functools import wraps

from fastmcp import FastMCP

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the MCP server
mcp = FastMCP("FreshRSS")

# --- Configuration and Session Management ---


class FreshRSSConfig:
    def __init__(self):
        self.base_url: Optional[str] = None
        self.auth_token: Optional[str] = None
        self.api_token: Optional[str] = None
        self.session: Optional[aiohttp.ClientSession] = None

    async def get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    def get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.auth_token:
            headers["Authorization"] = f"GoogleLogin auth={self.auth_token}"
        return headers

    async def authenticate(self, base_url: str, email: str, password: str) -> bool:
        """Authenticate with FreshRSS server and store credentials."""
        try:
            self.base_url = base_url.rstrip('/')
            session = await self.get_session()
            
            # Clear old tokens before re-authenticating
            self.auth_token = None
            self.api_token = None

            auth_url = urljoin(self.base_url, '/api/greader.php/accounts/ClientLogin')
            auth_data = {"Email": email, "Passwd": password}
            
            async with session.post(auth_url, data=auth_data) as response:
                if response.status != 200:
                    logger.error(f"Authentication failed with status: {response.status}")
                    return False
                
                auth_text = await response.text()
                auth_info = {key: value for key, value in (line.split('=', 1) for line in auth_text.strip().split('\n') if '=' in line)}

                if 'Auth' not in auth_info:
                    logger.error("Authentication response did not contain 'Auth' token.")
                    return False
                
                self.auth_token = auth_info['Auth']
                
                token_url = urljoin(self.base_url, '/api/greader.php/reader/api/0/token')
                async with session.get(token_url, headers=self.get_headers()) as token_response:
                    if token_response.status == 200:
                        self.api_token = (await token_response.text()).strip()
                
                logger.info(f"Successfully authenticated with FreshRSS at {self.base_url}")
                return True
                
        except aiohttp.ClientError as e:
            logger.exception(f"HTTP error during authentication: {e}")
            return False
        except Exception as e:
            logger.exception("An unexpected error occurred during authentication")
            return False

config = FreshRSSConfig()

# --- API Request Handling and Decorators ---

async def _api_request(method: str, url_path: str, **kwargs) -> Dict[str, Any]:
    """
    A centralized function to handle API requests, including authentication and re-authentication.
    """
    await ensure_authenticated()
    session = await config.get_session()
    url = urljoin(config.base_url, url_path)

    # For POST requests that need the API token, add it to the data payload
    if method.upper() == 'POST' and kwargs.get("requires_token"):
        data = kwargs.get("data", {})
        if not config.api_token:
            return {"error": "Missing API token for POST request."}
        data["T"] = config.api_token
        kwargs["data"] = data

    async def perform_request():
        return await session.request(method, url, headers=config.get_headers(), **kwargs)

    response = await perform_request()

    # Handle expired token: re-authenticate and retry once.
    if response.status == 401:
        logger.warning("Token expired (401 Unauthorized). Re-authenticating...")
        await ensure_authenticated(force=True)
        response = await perform_request() # Retry the request

    if response.status != 200:
        return {"error": f"API request failed: {response.status} {await response.text()}"}
    
    try:
        return await response.json()
    except (json.JSONDecodeError, aiohttp.ContentTypeError):
        return {"success": True, "message": await response.text()}


def authenticated_tool(func):
    """Decorator to handle authentication and error handling for MCP tools."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger.exception(f"Error in tool '{func.__name__}'")
            return {"error": str(e)}
    return wrapper

# --- MCP Tools ---

@mcp.tool()
@authenticated_tool
async def get_user_info() -> Dict[str, Any]:
    """
    Get information about the authenticated user.
    """
    return await _api_request("get", '/api/greader.php/reader/api/0/user-info')

@mcp.tool()
@authenticated_tool
async def list_all_subscriptions() -> Dict[str, Any]:
    """
    List all RSS feed subscriptions.
    """
    data = await _api_request("get", '/api/greader.php/reader/api/0/subscription/list')
    if "subscriptions" in data:
        data["subscriptions"] = [{
            "id": sub.get("id", ""),
            "title": sub.get("title", ""),
            "url": sub.get("url", ""),
            "htmlUrl": sub.get("htmlUrl", ""),
            "categories": [cat.get("label", "") for cat in sub.get("categories", [])]
        } for sub in data["subscriptions"]]
        data["count"] = len(data["subscriptions"])
    return data

@mcp.tool()
@authenticated_tool
async def list_subscriptions_by_category(category: str) -> Dict[str, Any]:
    """
    List RSS feed subscriptions filtered by a specific category.
    
    Args:
        category: The category to filter subscriptions by (case-insensitive).
    """
    data = await _api_request("get", '/api/greader.php/reader/api/0/subscription/list')
    if "subscriptions" in data:
        all_subscriptions = [{
            "id": sub.get("id", ""),
            "title": sub.get("title", ""),
            "url": sub.get("url", ""),
            "htmlUrl": sub.get("htmlUrl", ""),
            "categories": [cat.get("label", "") for cat in sub.get("categories", [])]
        } for sub in data["subscriptions"]]

        category_lower = category.lower()
        filtered_subs = [
            sub for sub in all_subscriptions
            if any(cat.lower() == category_lower for cat in sub["categories"])
        ]
        data["subscriptions"] = filtered_subs
        data["count"] = len(filtered_subs)
    return data

@mcp.tool()
@authenticated_tool
async def add_subscription(feed_url: str) -> Dict[str, Any]:
    """
    Add a new RSS feed subscription.
    """
    data = {"quickadd": feed_url}
    result = await _api_request("post", '/api/greader.php/reader/api/0/subscription/quickadd', data=data)
    if "error" not in result:
        return {
            "success": True,
            "message": f"Successfully added subscription: {result.get('streamName', feed_url)}",
            "details": result
        }
    return result

@mcp.tool()
@authenticated_tool
async def get_unread_counts() -> Dict[str, Any]:
    """
    Get unread article counts for all subscriptions and categories.
    """
    data = await _api_request("get", '/api/greader.php/reader/api/0/unread-count')
    if "unreadcounts" in data:
        total_unread = sum(item.get("count", 0) for item in data["unreadcounts"])
        return {
            "total_unread": total_unread,
            "max_items": data.get("max", 0),
            "unread_counts": [{
                "id": item.get("id", ""),
                "count": item.get("count", 0),
                "newest_timestamp": item.get("newestItemTimestampUsec", "")
            } for item in data["unreadcounts"]]
        }
    return data

def _format_articles(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Helper to format a list of article items."""
    formatted_articles = []
    for item in items:
        article = {
            "id": item.get("id", ""),
            "title": item.get("title", ""),
            "author": item.get("author", ""),
            "published": datetime.fromtimestamp(item.get("published", 0)).isoformat() if item.get("published") else "",
            "updated": datetime.fromtimestamp(item.get("updated", 0)).isoformat() if item.get("updated") else "",
            "summary": item.get("summary", {}).get("content", ""),
            "url": (item.get("alternate", [{}])[0].get("href", "")),
            "feed_title": item.get("origin", {}).get("title", ""),
            "feed_url": item.get("origin", {}).get("htmlUrl", "")
        }
        formatted_articles.append(article)
    return formatted_articles

async def _fetch_articles(stream_id: str, 
                        count: int, 
                        sort_order: str, 
                        exclude_target: Optional[str],
                        continuation: Optional[str]) -> Dict[str, Any]:
    """Internal function to fetch and format articles."""
    params = {"n": count, "r": sort_order}
    if exclude_target:
        params["xt"] = exclude_target
    if continuation:
        params["c"] = continuation
        
    # URL-encode the stream_id to handle special characters
    encoded_stream_id = urlencode({"a": stream_id})[2:]
    url_path = f'/api/greader.php/reader/api/0/stream/contents/{encoded_stream_id}'
    data = await _api_request("get", url_path, params=params)

    if "items" in data:
        formatted_articles = _format_articles(data["items"])
        return {
            "stream_id": data.get("id", stream_id),
            "updated": datetime.fromtimestamp(data.get("updated", 0)).isoformat() if data.get("updated") else "",
            "article_count": len(formatted_articles),
            "articles": formatted_articles,
            "continuation": data.get("continuation", "")
        }
    return data

@mcp.tool()
@authenticated_tool
async def get_articles(stream_id: str = "user/-/state/com.google/reading-list", 
                      count: int = 20, sort_order: str = "d", 
                      exclude_target: Optional[str] = None,
                      continuation: Optional[str] = None) -> Dict[str, Any]:
    """
    Get articles from a specific stream (feed, category, or reading list).
    """
    return await _fetch_articles(stream_id, count, sort_order, exclude_target, continuation)

@mcp.tool()
@authenticated_tool
async def search_articles(query: str, count: int = 20, search_in_stream: str = "user/-/state/com.google/reading-list") -> Dict[str, Any]:
    """
    Search for articles containing specific keywords by paginating through a stream.
    """
    query_lower = query.lower()
    matching_articles = []
    continuation = None
    
    while len(matching_articles) < count:
        # Call the internal fetch function directly
        page_result = await _fetch_articles(
            stream_id=search_in_stream,
            count=100, # Fetch a larger page size to reduce round trips
            sort_order='d',
            exclude_target=None,
            continuation=continuation
        )
        
        if "error" in page_result or not page_result.get("articles"):
            break # Stop if there's an error or no more articles

        for article in page_result["articles"]:
            if query_lower in article.get("title", "").lower() or query_lower in article.get("summary", "").lower():
                matching_articles.append(article)
                if len(matching_articles) >= count:
                    break
        
        continuation = page_result.get("continuation")
        if not continuation:
            break # No more pages

    return {
        "query": query,
        "match_count": len(matching_articles),
        "articles": matching_articles
    }

@mcp.tool()
@authenticated_tool
async def mark_article_read(article_id: str) -> Dict[str, Any]:
    """
    Mark a specific article as read.
    """
    data = {"i": article_id, "a": "user/-/state/com.google/read"}
    result = await _api_request("post", '/api/greader.php/reader/api/0/edit-tag', data=data, requires_token=True)
    if "error" not in result:
        return {"success": True, "message": f"Article {article_id} marked as read"}
    return result

@mcp.tool()
@authenticated_tool
async def mark_article_starred(article_id: str, starred: bool = True) -> Dict[str, Any]:
    """
    Mark or unmark an article as starred.
    """
    tag = "user/-/state/com.google/starred"
    data = {"i": article_id}
    if starred:
        data["a"] = tag
    else:
        data["r"] = tag
        
    result = await _api_request("post", '/api/greader.php/reader/api/0/edit-tag', data=data, requires_token=True)
    if "error" not in result:
        action = "starred" if starred else "unstarred"
        return {"success": True, "message": f"Article {article_id} {action}"}
    return result

@mcp.tool()
@authenticated_tool
async def get_starred_articles(count: int = 20) -> Dict[str, Any]:
    """
    Get all starred articles.
    """
    return await get_articles(stream_id="user/-/state/com.google/starred", count=count)

@mcp.tool()
@authenticated_tool
async def mark_all_as_read(stream_id: str) -> Dict[str, Any]:
    """
    Mark all articles in a stream as read.
    """
    data = {"s": stream_id}
    result = await _api_request("post", '/api/greader.php/reader/api/0/mark-all-as-read', data=data, requires_token=True)
    if "error" not in result:
        return {"success": True, "message": f"All articles in {stream_id} marked as read"}
    return result

@mcp.tool()
@authenticated_tool
async def list_categories() -> Dict[str, Any]:
    """
    List all available categories/tags.
    """
    data = await _api_request("get", '/api/greader.php/reader/api/0/tag/list')
    if "tags" in data:
        return {
            "count": len(data["tags"]),
            "categories": [{
                "id": tag.get("id", ""),
                "type": tag.get("type", ""),
                "unread_count": tag.get("unread_count", 0)
            } for tag in data["tags"]]
        }
    return data

# --- Server Initialization and Shutdown ---

async def ensure_authenticated(force: bool = False):
    """Ensure we're authenticated before making API calls, optionally forcing re-authentication."""
    if force or not config.auth_token:
        # Use global variables for credentials
        if not FRESHRSS_URL or not FRESHRSS_USER or not FRESHRSS_PASSWORD:
            raise Exception("Missing credentials for authentication. Please provide them via arguments or environment variables.")
        
        logger.info(f"{'Re-authenticating' if force else 'Authenticating'} with FreshRSS server at {FRESHRSS_URL}...")
        if not await config.authenticate(FRESHRSS_URL, FRESHRSS_USER, FRESHRSS_PASSWORD):
            raise Exception("Failed to authenticate. Please check your credentials and server URL.")

async def close_session():
    """Gracefully close the aiohttp session."""
    if config.session and not config.session.closed:
        await config.session.close()
        logger.info("Aiohttp session closed.")

def main():
    """Main function to initialize and run the MCP server."""
    parser = argparse.ArgumentParser(description='FreshRSS MCP Server')
    parser.add_argument('--url', help='FreshRSS server URL')
    parser.add_argument('--email', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    
    # Use parse_known_args to avoid conflicts with mcpo's arguments
    args, _ = parser.parse_known_args()

    # Set global variables for credentials
    global FRESHRSS_URL, FRESHRSS_USER, FRESHRSS_PASSWORD
    FRESHRSS_URL = args.url or os.getenv('FRESHRSS_URL')
    FRESHRSS_USER = args.email or os.getenv('FRESHRSS_EMAIL')
    FRESHRSS_PASSWORD = args.password or os.getenv('FRESHRSS_PASSWORD')

    if not all([FRESHRSS_URL, FRESHRSS_USER, FRESHRSS_PASSWORD]):
        logger.warning("Server starting without initial credentials. They must be provided before using tools.")

    logger.info("Starting FreshRSS MCP server...")
    try:
        mcp.run()
    finally:
        # Ensure the session is closed on exit
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                loop.create_task(close_session())
            else:
                asyncio.run(close_session())
        except RuntimeError: # No running loop
            pass

if __name__ == "__main__":
    main()
