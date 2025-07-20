# FreshRSS MCP Server

A Model Context Protocol (MCP) server for interacting with FreshRSS via its Google Reader compatible API. This server provides tools for browsing feeds, reading articles, and managing subscriptions. Authentication is handled during server startup.

## Features

### User Information
- `get_user_info()` - Get authenticated user information

### Feed Management
- `list_subscriptions()` - List all RSS feed subscriptions
- `add_subscription()` - Add new RSS feed subscription
- `list_categories()` - List all categories/tags with unread counts

### Article Reading
- `get_articles()` - Get articles from feeds, categories, or reading list
- `search_articles()` - Search articles by keywords
- `get_starred_articles()` - Get all starred articles
- `get_unread_counts()` - Get unread article counts by feed/category

### Article Management
- `mark_article_read()` - Mark specific article as read
- `mark_article_starred()` - Star/unstar articles
- `mark_all_as_read()` - Mark all articles in a stream as read

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the MCP server with your FreshRSS credentials:
```bash
# Using command line arguments
python freshrss_mcp_server.py --url https://your-freshrss-server.com --email your-email@example.com --password your-password

# Or using environment variables
export FRESHRSS_EMAIL="your-email@example.com"
export FRESHRSS_PASSWORD="your-password"
python freshrss_mcp_server.py --url https://your-freshrss-server.com
```

## Usage

Once the server is running and authenticated, you can use the available tools:

### Basic Operations
```python
# List subscriptions
subscriptions = await list_subscriptions()

# Get recent articles
articles = await get_articles(count=10)

# Search for articles
results = await search_articles("python", count=5)

# Mark article as read
await mark_article_read("article-id-here")

# Get unread counts
unread = await get_unread_counts()
```

### Stream IDs
Common stream IDs for getting articles:
- `user/-/state/com.google/reading-list` - All articles
- `user/-/state/com.google/starred` - Starred articles
- `user/-/state/com.google/read` - Read articles
- `feed/[feed-url]` - Specific feed
- `user/-/label/[category]` - Specific category

## Command Line Options

- `--url` (required): FreshRSS server URL
- `--email`: Email address for authentication (can also use FRESHRSS_EMAIL env var)
- `--password`: Password for authentication (can also use FRESHRSS_PASSWORD env var)

## API Compatibility

This server implements the Google Reader API endpoints that FreshRSS supports:
- Authentication (`/accounts/ClientLogin`) - handled at startup
- User info (`/reader/api/0/user-info`)
- Subscriptions (`/reader/api/0/subscription/list`, `/reader/api/0/subscription/quickadd`)
- Articles (`/reader/api/0/stream/contents/`)
- Tagging (`/reader/api/0/edit-tag`)
- Unread counts (`/reader/api/0/unread-count`)
- Categories (`/reader/api/0/tag/list`)

## Requirements

- Python 3.7+
- FastMCP library
- aiohttp for async HTTP requests
- FreshRSS server with API access enabled