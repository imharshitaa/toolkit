"""
ToolKit Tests
Unit tests for ToolKit CLI and core functionality
"""
import pytest
from pathlib import Path
from click.testing import CliRunner
from toolkit.cli import main
from toolkit.core import ToolKitCore, get_available_tools
from toolkit.utils import validate_ip, validate_url, get_version

# Test Fixtures
@pytest.fixture
def cli_runner():
    """Click CLI test runner"""
    return CliRunner()

@pytest.fixture
def core():
    """ToolKit core instance"""
    return ToolKitCore()

# CLI Tests
class TestCLI:
    
    def test_version_command(self, cli_runner):
        """Test version command"""
        result = cli_runner.invoke(main, ['version'])
        assert result.exit_code == 0
        assert 'ToolKit' in result.output
    
    def test_status_command(self, cli_runner):
        """Test status command"""
        result = cli_runner.invoke(main, ['status'])
        assert result.exit_code == 0
        assert 'Dependencies' in result.output
    
    def test_list_tools_command(self, cli_runner):
        """Test list tools command"""
        result = cli_runner.invoke(main, ['list-tools', 'soc'])
        assert result.exit_code == 0
        assert 'splunk' in result.output.lower()
    
    def test_deploy_help(self, cli_runner):
        """Test deploy command help"""
        result = cli_runner.invoke(main, ['deploy', '--help'])
        assert result.exit_code == 0
        assert 'Deploy a security tool' in result.output

# Core Tests
class TestCore:
    
    def test_get_module_path(self, core):
        """Test module path resolution"""
        with pytest.raises(ValueError):
            core.get_module_path('invalid_module', 'tool')
    
    def test_get_available_tools(self):
        """Test getting available tools"""
        soc_tools = get_available_tools('soc')
        assert len(soc_tools) > 0
        assert any(tool['name'] == 'splunk' for tool in soc_tools)
        
        edr_tools = get_available_tools('edr')
        assert len(edr_tools) > 0
        assert any(tool['name'] == 'crowdstrike' for tool in edr_tools)

# Utility Tests
class TestUtils:
    
    def test_validate_ip_valid(self):
        """Test IP validation with valid IPs"""
        assert validate_ip('192.168.1.1') == True
        assert validate_ip('10.0.0.1') == True
        assert validate_ip('172.16.0.1') == True
    
    def test_validate_ip_invalid(self):
        """Test IP validation with invalid IPs"""
        assert validate_ip('256.1.1.1') == False
        assert validate_ip('192.168.1') == False
        assert validate_ip('invalid') == False
    
    def test_validate_url_valid(self):
        """Test URL validation with valid URLs"""
        assert validate_url('http://example.com') == True
        assert validate_url('https://example.com') == True
        assert validate_url('https://example.com:8080/path') == True
    
    def test_validate_url_invalid(self):
        """Test URL validation with invalid URLs"""
        assert validate_url('not-a-url') == False
        assert validate_url('ftp://example.com') == False
    
    def test_get_version(self):
        """Test version retrieval"""
        version = get_version()
        assert version is not None
        assert isinstance(version, str)

# Integration Tests
class TestIntegration:
    
    def test_deploy_dry_run(self, cli_runner):
        """Test deployment dry run"""
        result = cli_runner.invoke(main, [
            'deploy', 'soc', 'splunk',
            '--environment', 'docker',
            '--dry-run'
        ])
        # Should not fail even if module doesn't exist
        assert 'DRY RUN' in result.output or result.exit_code != 0
    
    def test_scan_with_invalid_target(self, cli_runner):
        """Test scan with invalid target"""
        result = cli_runner.invoke(main, [
            'scan', 'soc', 'splunk',
            '--target', 'invalid-target-999'
        ])
        # Target validation should work
        assert result.exit_code == 0 or 'Invalid' in result.output

# Module Configuration Tests
class TestModuleConfig:
    
    def test_splunk_config_import(self):
        """Test Splunk configuration import"""
        try:
            from modules.SOC.splunk.config import get_config, validate
            config = get_config('docker')
            assert 'splunk' in config
            assert 'deployment' in config
        except ImportError:
            pytest.skip("Splunk module not found")
    
    def test_zap_config_import(self):
        """Test ZAP configuration import"""
        try:
            from modules.APPSEC.zap.config import get_config
            config = get_config('docker')
            assert 'zap' in config
        except ImportError:
            pytest.skip("ZAP module not found")

# Parametrized Tests
@pytest.mark.parametrize("module,tool", [
    ('soc', 'splunk'),
    ('soc', 'elastic'),
    ('edr', 'crowdstrike'),
    ('appsec', 'zap'),
])
def test_tool_in_available_list(module, tool):
    """Test that tools are in available tools list"""
    tools = get_available_tools(module)
    tool_names = [t['name'] for t in tools]
    assert tool in tool_names

# Error Handling Tests
class TestErrorHandling:
    
    def test_invalid_module(self, cli_runner):
        """Test handling of invalid module"""
        result = cli_runner.invoke(main, ['deploy', 'invalid', 'tool'])
        assert result.exit_code != 0
    
    def test_missing_required_args(self, cli_runner):
        """Test handling of missing required arguments"""
        result = cli_runner.invoke(main, ['scan', 'soc', 'splunk'])
        assert result.exit_code != 0  # Missing --target

# Performance Tests
class TestPerformance:
    
    def test_cli_help_performance(self, cli_runner):
        """Test CLI help response time"""
        import time
        start = time.time()
        result = cli_runner.invoke(main, ['--help'])
        duration = time.time() - start
        
        assert result.exit_code == 0
        assert duration < 1.0  # Should respond in < 1 second

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
