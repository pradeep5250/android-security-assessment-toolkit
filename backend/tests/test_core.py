"""Tests for the risk scoring engine and validators."""

import pytest
from app.core.risk_scorer import (
    calculate_risk_score,
    get_risk_level,
    aggregate_findings,
    generate_recommendations,
)
from app.utils.validators import (
    validate_ip_address,
    validate_hostname,
    validate_port,
    validate_port_range,
    validate_package_name,
    sanitize_filename,
)
from app.utils.adb_commands import (
    build_command,
    sanitize_argument,
    ADBCommandError,
)


# ── Risk Scorer Tests ────────────────────────────────────────────────────────

class TestRiskScorer:
    def test_empty_findings(self):
        assert calculate_risk_score([]) == 0.0

    def test_single_critical(self):
        findings = [{"severity": "critical", "title": "test"}]
        assert calculate_risk_score(findings) == 25.0

    def test_mixed_severities(self):
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]
        score = calculate_risk_score(findings)
        assert score == 25 + 15 + 8 + 3 + 1  # 52

    def test_score_capped_at_100(self):
        findings = [{"severity": "critical"}] * 10
        assert calculate_risk_score(findings) == 100.0

    def test_risk_level_minimal(self):
        result = get_risk_level(5)
        assert result["level"] == "Minimal"

    def test_risk_level_critical(self):
        result = get_risk_level(90)
        assert result["level"] == "Critical"

    def test_aggregate_findings(self):
        f1 = [{"severity": "high", "title": "A"}]
        f2 = [{"severity": "low", "title": "B"}]
        result = aggregate_findings([f1, f2])
        assert result["total_findings"] == 2
        assert result["by_severity"]["high"] == 1
        assert result["by_severity"]["low"] == 1

    def test_generate_recommendations(self):
        findings = [
            {"severity": "high", "title": "A", "recommendation": "Fix A", "category": "Net"},
            {"severity": "low", "title": "B", "recommendation": "Fix B", "category": "Net"},
        ]
        recs = generate_recommendations(findings)
        assert len(recs) == 2
        assert recs[0]["priority"] == "high"  # Critical first


# ── Validator Tests ──────────────────────────────────────────────────────────

class TestValidators:
    def test_valid_ip(self):
        assert validate_ip_address("192.168.1.1") is True
        assert validate_ip_address("10.0.0.1") is True

    def test_invalid_ip(self):
        assert validate_ip_address("999.999.999.999") is False
        assert validate_ip_address("abc") is False
        assert validate_ip_address("") is False

    def test_valid_hostname(self):
        assert validate_hostname("example.com") is True
        assert validate_hostname("sub.example.com") is True

    def test_invalid_hostname(self):
        assert validate_hostname("-invalid.com") is False
        assert validate_hostname("a" * 300) is False

    def test_valid_port(self):
        assert validate_port(80) is True
        assert validate_port(65535) is True
        assert validate_port(1) is True

    def test_invalid_port(self):
        assert validate_port(0) is False
        assert validate_port(65536) is False
        assert validate_port(-1) is False

    def test_port_range_single(self):
        assert validate_port_range("80") == [80]

    def test_port_range_list(self):
        assert validate_port_range("80,443,8080") == [80, 443, 8080]

    def test_port_range_range(self):
        result = validate_port_range("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_port_range_common(self):
        result = validate_port_range("common")
        assert len(result) > 10

    def test_port_range_invalid(self):
        assert validate_port_range("abc") is None
        assert validate_port_range("0-100000") is None

    def test_valid_package_name(self):
        assert validate_package_name("com.example.app") is True
        assert validate_package_name("org.test.myapp") is True

    def test_invalid_package_name(self):
        assert validate_package_name("noperiod") is False
        assert validate_package_name(".leading.dot") is False

    def test_sanitize_filename(self):
        assert sanitize_filename("test<file>.apk") == "test_file_.apk"


# ── ADB Command Builder Tests ───────────────────────────────────────────────

class TestADBCommands:
    def test_build_basic_command(self):
        cmd = build_command("devices")
        assert cmd[-1] == "devices"

    def test_build_command_with_serial(self):
        cmd = build_command("shell", ["getprop"], serial="abc123")
        assert "-s" in cmd
        assert "abc123" in cmd

    def test_disallowed_command(self):
        with pytest.raises(ADBCommandError):
            build_command("root")

    def test_dangerous_chars_rejected(self):
        with pytest.raises(ADBCommandError):
            sanitize_argument("test;rm -rf")

    def test_shell_whitelist(self):
        with pytest.raises(ADBCommandError):
            build_command("shell", ["rm", "-rf", "/"])

    def test_allowed_shell_command(self):
        cmd = build_command("shell", ["getprop", "ro.build.version.release"], serial="dev1")
        assert "getprop" in cmd
