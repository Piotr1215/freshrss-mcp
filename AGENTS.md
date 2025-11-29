# AGENTS.md

## Build
python -m build

## Lint
pylint --disable=C0103

## Test
pytest tests/test_mark_article_read.py

## Style
- Alphabetical imports
- 4-space indentation
- LF line endings
- snake_case for vars/functions
- PascalCase for classes
- Type hints
- try-except for critical ops

## Testing
- Must be in `tests/`
- File names end with `.py`
- Tests should be idempotent

## Security
- Secrets in `.env`
- Never commit `.env`