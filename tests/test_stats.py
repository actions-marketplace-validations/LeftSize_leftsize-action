"""Tests for stats.py - stats mode functionality"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

# Import the functions to test
from stats import (
    fetch_stats,
    extract_key_metrics,
    get_repo_info,
    set_github_output,
    stats_main
)


class TestFetchStats:
    """Tests for the fetch_stats function"""

    @patch('stats.requests.get')
    def test_fetch_stats_markdown_success(self, mock_get):
        """Test successful markdown format fetch"""
        mock_response = MagicMock()
        mock_response.text = "# Report\n\nSome markdown content"
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = fetch_stats(
            backend_url='https://api.leftsize.com',
            installation_id='12345',
            repository_token='test-token-uuid',
            owner='testowner',
            repo='testrepo',
            period='30d',
            format='markdown',
            report='summary'
        )

        assert result['success'] is True
        assert result['report'] == "# Report\n\nSome markdown content"
        assert result['stats'] is None

    @patch('stats.requests.get')
    def test_fetch_stats_json_success(self, mock_get):
        """Test successful JSON format fetch"""
        stats_data = {
            'Overview': {'TotalFindings': 10, 'FixRatio': 0.75},
            'Savings': {'PotentialMonthlySavings': 100.50}
        }
        mock_response = MagicMock()
        mock_response.json.return_value = stats_data
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = fetch_stats(
            backend_url='https://api.leftsize.com',
            installation_id='12345',
            repository_token='test-token-uuid',
            owner='testowner',
            repo='testrepo',
            period='30d',
            format='json',
            report='summary'
        )

        assert result['success'] is True
        assert result['stats'] == stats_data
        assert 'TotalFindings' in result['report']

    @patch('stats.requests.get')
    def test_fetch_stats_http_error(self, mock_get):
        """Test HTTP error handling"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = Exception("404 Not Found")
        mock_get.return_value = mock_response

        result = fetch_stats(
            backend_url='https://api.leftsize.com',
            installation_id='12345',
            repository_token='test-token-uuid',
            owner='testowner',
            repo='testrepo'
        )

        assert result['success'] is False
        assert result['error'] is not None

    @patch('stats.requests.get')
    def test_fetch_stats_timeout(self, mock_get):
        """Test timeout handling"""
        import requests
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

        result = fetch_stats(
            backend_url='https://api.leftsize.com',
            installation_id='12345',
            repository_token='test-token-uuid',
            owner='testowner',
            repo='testrepo'
        )

        assert result['success'] is False
        assert 'timed out' in result['error'].lower()


class TestExtractKeyMetrics:
    """Tests for the extract_key_metrics function"""

    def test_extract_metrics_success(self):
        """Test successful metric extraction"""
        stats = {
            'Overview': {'FixRatio': 0.75},
            'Savings': {
                'PotentialMonthlySavings': 150.50,
                'RealizedMonthlySavings': 100.25
            }
        }

        metrics = extract_key_metrics(stats)

        assert metrics['fix_ratio'] == '75.0'
        assert metrics['potential_savings'] == '150.5'
        assert metrics['realized_savings'] == '100.25'

    def test_extract_metrics_empty_stats(self):
        """Test with empty stats"""
        metrics = extract_key_metrics({})

        assert metrics['fix_ratio'] == '0'
        assert metrics['potential_savings'] == '0'
        assert metrics['realized_savings'] == '0'

    def test_extract_metrics_none_stats(self):
        """Test with None stats"""
        metrics = extract_key_metrics(None)

        assert metrics['fix_ratio'] == '0'
        assert metrics['potential_savings'] == '0'
        assert metrics['realized_savings'] == '0'

    def test_extract_metrics_missing_fields(self):
        """Test with partially missing fields"""
        stats = {
            'Overview': {},
            'Savings': {'PotentialMonthlySavings': 50}
        }

        metrics = extract_key_metrics(stats)

        assert metrics['fix_ratio'] == '0'
        # Note: round(50.0, 2) = 50 (no trailing decimal)
        assert float(metrics['potential_savings']) == 50.0
        assert metrics['realized_savings'] == '0'


class TestGetRepoInfo:
    """Tests for the get_repo_info function"""

    def test_get_repo_info_success(self):
        """Test successful repo info extraction"""
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'myorg/myrepo'}):
            owner, repo = get_repo_info()
            assert owner == 'myorg'
            assert repo == 'myrepo'

    def test_get_repo_info_nested_org(self):
        """Test repo info with nested path"""
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'myorg/my/nested/repo'}):
            owner, repo = get_repo_info()
            assert owner == 'myorg'
            assert repo == 'my/nested/repo'

    def test_get_repo_info_missing(self):
        """Test with missing GITHUB_REPOSITORY"""
        with patch.dict(os.environ, {}, clear=True):
            # Ensure GITHUB_REPOSITORY is not set
            if 'GITHUB_REPOSITORY' in os.environ:
                del os.environ['GITHUB_REPOSITORY']
            owner, repo = get_repo_info()
            assert owner == ''
            assert repo == ''

    def test_get_repo_info_invalid_format(self):
        """Test with invalid format (no slash)"""
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'invalid-format'}):
            owner, repo = get_repo_info()
            assert owner == ''
            assert repo == ''


class TestSetGithubOutput:
    """Tests for the set_github_output function"""

    def test_set_output_simple(self, tmp_path):
        """Test setting a simple output"""
        output_file = tmp_path / "github_output"
        output_file.touch()
        
        with patch.dict(os.environ, {'GITHUB_OUTPUT': str(output_file)}):
            set_github_output('test-key', 'test-value')
        
        content = output_file.read_text()
        assert 'test-key=test-value' in content

    def test_set_output_multiline(self, tmp_path):
        """Test setting a multiline output"""
        output_file = tmp_path / "github_output"
        output_file.touch()
        
        with patch.dict(os.environ, {'GITHUB_OUTPUT': str(output_file)}):
            set_github_output('multiline', 'line1\nline2\nline3')
        
        content = output_file.read_text()
        assert 'multiline<<EOF_' in content
        assert 'line1\nline2\nline3' in content


class TestStatsMain:
    """Tests for the stats_main function"""

    @patch('stats.fetch_stats')
    @patch('stats.set_github_output')
    @patch('stats.print_stats_summary')
    def test_stats_main_success(self, mock_summary, mock_output, mock_fetch):
        """Test successful stats_main execution"""
        mock_fetch.return_value = {
            'success': True,
            'report': '# Report',
            'stats': {
                'Overview': {'FixRatio': 0.5},
                'Savings': {'PotentialMonthlySavings': 100, 'RealizedMonthlySavings': 50}
            }
        }

        env_vars = {
            'LEFTSIZE_INSTALLATION_ID': '12345',
            'LEFTSIZE_REPOSITORY_TOKEN': 'test-token',
            'GITHUB_REPOSITORY': 'owner/repo'
        }

        with patch.dict(os.environ, env_vars):
            result = stats_main()

        assert result == 0
        mock_fetch.assert_called_once()

    @patch('stats.set_github_output')
    def test_stats_main_missing_installation_id(self, mock_output):
        """Test stats_main with missing installation ID"""
        env_vars = {
            'LEFTSIZE_REPOSITORY_TOKEN': 'test-token',
            'GITHUB_REPOSITORY': 'owner/repo'
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if 'LEFTSIZE_INSTALLATION_ID' in os.environ:
                del os.environ['LEFTSIZE_INSTALLATION_ID']
            result = stats_main()

        assert result == 1

    @patch('stats.set_github_output')
    def test_stats_main_invalid_period(self, mock_output):
        """Test stats_main with invalid period"""
        env_vars = {
            'LEFTSIZE_INSTALLATION_ID': '12345',
            'LEFTSIZE_REPOSITORY_TOKEN': 'test-token',
            'LEFTSIZE_PERIOD': 'invalid',
            'GITHUB_REPOSITORY': 'owner/repo'
        }

        with patch.dict(os.environ, env_vars):
            result = stats_main()

        assert result == 1

    @patch('stats.fetch_stats')
    @patch('stats.set_github_output')
    def test_stats_main_fetch_failure(self, mock_output, mock_fetch):
        """Test stats_main when fetch fails"""
        mock_fetch.return_value = {
            'success': False,
            'error': 'Connection failed',
            'report': None,
            'stats': None
        }

        env_vars = {
            'LEFTSIZE_INSTALLATION_ID': '12345',
            'LEFTSIZE_REPOSITORY_TOKEN': 'test-token',
            'GITHUB_REPOSITORY': 'owner/repo'
        }

        with patch.dict(os.environ, env_vars):
            result = stats_main()

        assert result == 1
