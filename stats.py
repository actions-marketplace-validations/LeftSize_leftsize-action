#!/usr/bin/env python3
"""
LeftSize Stats - Python module for fetching and displaying repository statistics
"""

import os
import json
import logging
from typing import Dict, Any, Optional
import requests
import structlog

logger = structlog.get_logger()


def fetch_stats(
    backend_url: str,
    installation_id: str,
    repository_token: str,
    owner: str,
    repo: str,
    period: str = '30d',
    format: str = 'markdown',
    report: str = 'summary'
) -> Dict[str, Any]:
    """
    Fetch statistics from the LeftSize backend API
    
    Returns a dict with:
    - success: bool
    - report: str (markdown or json content)
    - stats: dict (raw stats data, only for json format)
    - error: str (if success is False)
    """
    
    url = f"{backend_url}/api/stats/{installation_id}/{owner}/{repo}"
    params = {
        'period': period,
        'format': format,
        'report': report
    }
    headers = {
        'Authorization': f'Bearer {repository_token}',
        'User-Agent': 'LeftSize-Action/1.0',
        'Accept': 'text/markdown' if format == 'markdown' else 'application/json'
    }
    
    logger.info(
        "Fetching stats from backend",
        url=url,
        period=period,
        format=format,
        report=report
    )
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        
        if format == 'markdown':
            return {
                'success': True,
                'report': response.text,
                'stats': None
            }
        else:
            stats_data = response.json()
            return {
                'success': True,
                'report': json.dumps(stats_data, indent=2, default=str),
                'stats': stats_data
            }
            
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response else 'unknown'
        logger.error("HTTP error fetching stats", status_code=status_code, error=str(e))
        return {
            'success': False,
            'error': f"HTTP {status_code}: {str(e)}",
            'report': None,
            'stats': None
        }
    except requests.exceptions.RequestException as e:
        logger.error("Request error fetching stats", error=str(e))
        return {
            'success': False,
            'error': str(e),
            'report': None,
            'stats': None
        }
    except Exception as e:
        logger.error("Unexpected error fetching stats", error=str(e))
        return {
            'success': False,
            'error': str(e),
            'report': None,
            'stats': None
        }


def extract_key_metrics(stats: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract key metrics from stats response for GitHub Action outputs
    """
    if not stats:
        return {
            'fix_ratio': '0',
            'potential_savings': '0',
            'realized_savings': '0'
        }
    
    overview = stats.get('Overview', {})
    savings = stats.get('Savings', {})
    
    return {
        'fix_ratio': str(round(overview.get('FixRatio', 0) * 100, 1)),
        'potential_savings': str(round(savings.get('PotentialMonthlySavings', 0), 2)),
        'realized_savings': str(round(savings.get('RealizedMonthlySavings', 0), 2))
    }


def get_repo_info() -> tuple[str, str]:
    """
    Get repository owner and name from GitHub environment
    
    Returns (owner, repo) tuple
    """
    github_repository = os.getenv('GITHUB_REPOSITORY', '')
    if '/' in github_repository:
        parts = github_repository.split('/', 1)
        return parts[0], parts[1]
    return '', ''


def stats_main() -> int:
    """
    Stats mode entry point - reads from environment variables, fetches stats, sets outputs
    
    Returns exit code (0 for success, 1 for failure)
    """
    
    # Read configuration from environment
    verbose = os.getenv('LEFTSIZE_VERBOSE', 'false').lower() == 'true'
    backend_url = os.getenv('LEFTSIZE_BACKEND_URL', 'https://api.leftsize.com')
    installation_id = os.getenv('LEFTSIZE_INSTALLATION_ID', '')
    repository_token = os.getenv('LEFTSIZE_REPOSITORY_TOKEN', '')
    period = os.getenv('LEFTSIZE_PERIOD', '30d')
    format = os.getenv('LEFTSIZE_FORMAT', 'markdown')
    report = os.getenv('LEFTSIZE_REPORT', 'summary')
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    logger.info("LeftSize Stats mode starting", version="1.0.0")
    
    # Validate required inputs
    if not installation_id:
        logger.error("Missing required input: installation-id")
        set_github_output('report', '')
        return 1
    
    if not repository_token:
        logger.error("Missing required input: repository-token")
        set_github_output('report', '')
        return 1
    
    # Validate period
    valid_periods = ['7d', '30d', '90d', 'all']
    if period not in valid_periods:
        logger.error("Invalid period. Must be one of: 7d, 30d, 90d, all", period=period)
        set_github_output('report', '')
        return 1
    
    # Validate format
    valid_formats = ['json', 'markdown']
    if format not in valid_formats:
        logger.error("Invalid format. Must be one of: json, markdown", format=format)
        set_github_output('report', '')
        return 1
    
    # Validate report type
    valid_reports = ['summary', 'detailed', 'executive']
    if report not in valid_reports:
        logger.error("Invalid report type. Must be one of: summary, detailed, executive", report=report)
        set_github_output('report', '')
        return 1
    
    # Get repository info from GitHub environment
    owner, repo = get_repo_info()
    if not owner or not repo:
        logger.error("Could not determine repository from GITHUB_REPOSITORY environment variable")
        set_github_output('report', '')
        return 1
    
    logger.info(
        "Fetching stats",
        owner=owner,
        repo=repo,
        period=period,
        format=format,
        report=report
    )
    
    # Fetch stats from backend
    result = fetch_stats(
        backend_url=backend_url,
        installation_id=installation_id,
        repository_token=repository_token,
        owner=owner,
        repo=repo,
        period=period,
        format=format,
        report=report
    )
    
    if not result['success']:
        logger.error("Failed to fetch stats", error=result.get('error', 'Unknown error'))
        set_github_output('report', '')
        set_github_output('stats-json', '{}')
        set_github_output('fix-ratio', '0')
        set_github_output('potential-savings', '0')
        set_github_output('realized-savings', '0')
        return 1
    
    # Set GitHub Action outputs
    report_content = result.get('report', '')
    set_github_output('report', report_content)
    
    # If we have raw stats (json format), set additional outputs
    stats_data = result.get('stats')
    if stats_data:
        set_github_output('stats-json', json.dumps(stats_data, default=str))
        metrics = extract_key_metrics(stats_data)
        set_github_output('fix-ratio', metrics['fix_ratio'])
        set_github_output('potential-savings', metrics['potential_savings'])
        set_github_output('realized-savings', metrics['realized_savings'])
    else:
        # For markdown format, we need to make another request to get raw stats
        # for the additional outputs
        json_result = fetch_stats(
            backend_url=backend_url,
            installation_id=installation_id,
            repository_token=repository_token,
            owner=owner,
            repo=repo,
            period=period,
            format='json',
            report=report
        )
        if json_result['success'] and json_result.get('stats'):
            stats_data = json_result['stats']
            set_github_output('stats-json', json.dumps(stats_data, default=str))
            metrics = extract_key_metrics(stats_data)
            set_github_output('fix-ratio', metrics['fix_ratio'])
            set_github_output('potential-savings', metrics['potential_savings'])
            set_github_output('realized-savings', metrics['realized_savings'])
        else:
            set_github_output('stats-json', '{}')
            set_github_output('fix-ratio', '0')
            set_github_output('potential-savings', '0')
            set_github_output('realized-savings', '0')
    
    # Print summary to GitHub Actions job summary
    print_stats_summary(report_content, format)
    
    logger.info("LeftSize Stats completed successfully")
    return 0


def set_github_output(name: str, value: str):
    """Set GitHub Actions output"""
    github_output = os.getenv('GITHUB_OUTPUT')
    if github_output:
        # Handle multiline values using heredoc syntax
        if '\n' in value:
            import uuid
            delimiter = f"EOF_{uuid.uuid4().hex[:8]}"
            with open(github_output, 'a') as f:
                f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            with open(github_output, 'a') as f:
                f.write(f"{name}={value}\n")
    else:
        # Fallback for testing (deprecated syntax)
        if '\n' in value:
            # Can't easily handle multiline in old syntax
            print(f"::set-output name={name}::[multiline content]")
        else:
            print(f"::set-output name={name}::{value}")


def print_stats_summary(report_content: str, format: str):
    """Print stats to GitHub Actions job summary"""
    github_step_summary = os.getenv('GITHUB_STEP_SUMMARY')
    
    if format == 'markdown':
        summary = report_content
    else:
        # For JSON format, create a simple markdown summary
        summary = f"""# LeftSize Statistics Report

```json
{report_content[:5000]}{"..." if len(report_content) > 5000 else ""}
```
"""
    
    if github_step_summary:
        with open(github_step_summary, 'a') as f:
            f.write(summary)
    else:
        print(summary)


if __name__ == "__main__":
    import sys
    sys.exit(stats_main())
