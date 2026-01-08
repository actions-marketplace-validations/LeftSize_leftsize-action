"""
Tests for API submission and token handling in run.py

These tests verify:
- Token is sent via Authorization header (not in URL)
- Token is not logged
- API submission handles errors properly
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

# Add parent directory to path to import run module
sys.path.insert(0, str(Path(__file__).parent.parent))

from run import submit_findings, group_findings


class TestSubmitFindings:
    """Tests for the submit_findings function"""
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_token_in_authorization_header(self, mock_logger, mock_post):
        """Token should be sent via Authorization header, not in URL"""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_response.json.return_value = {"message": "accepted"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        findings = [{
            "ruleId": "test-rule",
            "scope": "test-scope",
            "resourceId": "/test/resource",
            "metadata": {}
        }]
        
        # Config must have 'output' key wrapping the settings
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        submit_findings(findings, config)
        
        # Verify the call was made
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        
        # Get URL from positional or keyword args
        url = call_args.args[0] if call_args.args else call_args.kwargs.get('url')
        
        # Verify the URL does NOT contain the token
        assert "12345678-1234-1234-1234-123456789012" not in url
        assert url == "https://api.leftsize.com/findings/12345"
        
        # Verify token is in Authorization header
        headers = call_args.kwargs.get('headers', {})
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer 12345678-1234-1234-1234-123456789012"
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_token_not_logged(self, mock_logger, mock_post):
        """Token should NOT appear in log messages"""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_response.json.return_value = {"message": "accepted"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        token = "12345678-1234-1234-1234-123456789012"
        findings = [{
            "ruleId": "test-rule",
            "scope": "test-scope",
            "resourceId": "/test/resource",
            "metadata": {}
        }]
        
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": token
            }
        }
        
        submit_findings(findings, config)
        
        # Check all log calls don't contain the token
        for call in mock_logger.info.call_args_list:
            call_str = str(call)
            assert token not in call_str, f"Token found in log: {call_str}"
        
        for call in mock_logger.warning.call_args_list:
            call_str = str(call)
            assert token not in call_str, f"Token found in log: {call_str}"
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_skips_submission_without_backend_url(self, mock_logger, mock_post):
        """Should skip submission if backend URL is not configured"""
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        submit_findings(findings, config)
        
        mock_post.assert_not_called()
        mock_logger.warning.assert_called()
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_skips_submission_without_token(self, mock_logger, mock_post):
        """Should skip submission if repository token is not configured"""
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345"
            }
        }
        
        submit_findings(findings, config)
        
        mock_post.assert_not_called()
        mock_logger.warning.assert_called()
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_handles_api_error(self, mock_logger, mock_post):
        """Should log error on API failure (exception is caught internally)"""
        from requests.exceptions import HTTPError
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = HTTPError("Server error")
        mock_post.return_value = mock_response
        
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        # The function re-raises the exception
        with pytest.raises(Exception):
            submit_findings(findings, config)
        
        mock_logger.error.assert_called()
    
    @patch('run.requests.post')
    @patch('run.logger')
    def test_request_timeout(self, mock_logger, mock_post):
        """Should use 30 second timeout for API requests"""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_response.json.return_value = {"message": "accepted"}
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        config = {
            "output": {
                "backend_url": "https://api.leftsize.com",
                "installation_id": "12345",
                "repository_token": "12345678-1234-1234-1234-123456789012"
            }
        }
        
        submit_findings(findings, config)
        
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args.kwargs.get('timeout') == 30


class TestGroupFindings:
    """Tests for the group_findings function"""
    
    def test_groups_by_rule_and_scope(self):
        """Findings should be grouped by ruleId and scope"""
        findings = [
            {"ruleId": "rule1", "scope": "scope1", "resourceId": "/r1", "metadata": {}},
            {"ruleId": "rule1", "scope": "scope1", "resourceId": "/r2", "metadata": {}},
            {"ruleId": "rule1", "scope": "scope2", "resourceId": "/r3", "metadata": {}},
            {"ruleId": "rule2", "scope": "scope1", "resourceId": "/r4", "metadata": {}},
        ]
        
        groups = group_findings(findings)
        
        assert len(groups) == 3  # 3 unique (ruleId, scope) combinations
        
        # Find group for rule1/scope1
        rule1_scope1 = next(g for g in groups if g["RuleId"] == "rule1" and g["Scope"] == "scope1")
        assert len(rule1_scope1["Findings"]) == 2
    
    def test_uses_pascal_case(self):
        """Output should use PascalCase for backend compatibility"""
        findings = [{"ruleId": "test", "scope": "test", "resourceId": "/test", "metadata": {}}]
        
        groups = group_findings(findings)
        
        assert "RuleId" in groups[0]
        assert "Scope" in groups[0]
        assert "Findings" in groups[0]
    
    def test_empty_findings(self):
        """Empty findings list should return empty groups"""
        groups = group_findings([])
        assert groups == []
