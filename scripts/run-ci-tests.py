#!/usr/bin/env python3
"""
Local CI Test Runner

Runs the same test suite as GitHub Actions CI/CD pipeline locally.
Mirrors the exact test sequence from .github/workflows/ci.yml
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Optional


class Colors:
    """ANSI color codes for terminal output"""

    BLUE = "\033[0;34m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    NC = "\033[0m"  # No Color


class TestRunner:
    """Runs the complete CI test suite locally"""

    def __init__(self, args):
        self.args = args
        self.project_root = Path(__file__).parent.parent
        self.results = {}
        self.start_time = time.time()
        self.xgt_container = None
        self.xgt_port = None

    def log(self, message: str, color: str = Colors.NC):
        """Print colored log message"""

    def run_command(self, cmd: list[str], name: str, cwd: Optional[Path] = None, env: Optional[dict] = None) -> tuple[bool, str]:
        """Run a command and capture output"""
        self.log(f"🔄 Running: {name}", Colors.BLUE)

        if cwd is None:
            cwd = self.project_root

        # Merge environment
        full_env = os.environ.copy()
        if env:
            full_env.update(env)

        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                env=full_env,
                timeout=600,  # 10 minute timeout
            )

            if result.returncode == 0:
                self.log(f"✅ {name} - PASSED", Colors.GREEN)
                return True, result.stdout
            else:
                self.log(f"❌ {name} - FAILED", Colors.RED)
                self.log(f"STDOUT:\n{result.stdout}", Colors.YELLOW)
                self.log(f"STDERR:\n{result.stderr}", Colors.RED)
                return False, result.stderr

        except subprocess.TimeoutExpired:
            self.log(f"⏰ {name} - TIMEOUT", Colors.RED)
            return False, "Command timed out"
        except Exception as e:
            self.log(f"💥 {name} - ERROR: {e}", Colors.RED)
            return False, str(e)

    def check_requirements(self) -> bool:
        """Check if required tools are available"""
        self.log("🔍 Checking requirements...", Colors.CYAN)

        required_tools = ["python3", "pip", "docker"]
        missing = []

        for tool in required_tools:
            if not shutil.which(tool):
                missing.append(tool)

        if missing:
            self.log(f"❌ Missing required tools: {', '.join(missing)}", Colors.RED)
            return False

        # Check if we're in the right directory
        if not (self.project_root / "pyproject.toml").exists():
            self.log("❌ Not in project root directory", Colors.RED)
            return False

        self.log("✅ All requirements met", Colors.GREEN)
        return True

    def setup_environment(self) -> bool:
        """Set up Python environment and dependencies"""
        self.log("🐍 Setting up Python environment...", Colors.CYAN)

        # Install/upgrade pip
        success, _ = self.run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], "Upgrade pip")
        if not success:
            return False

        # Install dependencies
        success, _ = self.run_command(
            [sys.executable, "-m", "pip", "install", "-r", "requirements/development.txt"],
            "Install dependencies",
        )

        return success

    def run_code_quality_checks(self) -> bool:
        """Run code quality checks (mirrors code-quality job)"""
        self.log("\n🔍 Code Quality & Security Checks", Colors.PURPLE)

        checks = [
            # Linting with ruff
            (
                [sys.executable, "-m", "ruff", "check", ".", "--output-format=github"],
                "Ruff lint check",
            ),
            ([sys.executable, "-m", "ruff", "format", "--check", "."], "Ruff format check"),
            # Type checking with mypy
            ([sys.executable, "-m", "mypy", "app/", "--ignore-missing-imports"], "MyPy type check"),
            # Security check with bandit
            (
                [
                    sys.executable,
                    "-m",
                    "bandit",
                    "-r",
                    "app/",
                    "-f",
                    "json",
                    "-o",
                    "bandit-report.json",
                ],
                "Bandit security scan",
            ),
        ]

        all_passed = True
        for cmd, name in checks:
            success, _ = self.run_command(cmd, name)
            self.results[name] = success
            if not success:
                all_passed = False

        return all_passed

    def run_unit_tests(self) -> bool:
        """Run unit tests (mirrors test job)"""
        self.log("\n🧪 Unit Tests", Colors.PURPLE)

        # Test multiple Python versions if available, otherwise just current
        python_versions = []
        if self.args.all_python_versions:
            for version in ["3.9", "3.10", "3.11"]:
                if shutil.which(f"python{version}"):
                    python_versions.append(f"python{version}")

        if not python_versions:
            python_versions = [sys.executable]

        all_passed = True
        for python_cmd in python_versions:
            cmd = [
                python_cmd,
                "-m",
                "pytest",
                "tests/unit/",
                "--cov=app",
                "--cov-report=xml",
                "--cov-report=html",
                "--cov-fail-under=20",
                "--junitxml=junit.xml",
                "-v",
            ]

            success, _ = self.run_command(cmd, f"Unit tests ({python_cmd})")
            self.results[f"Unit tests ({python_cmd})"] = success
            if not success:
                all_passed = False

        return all_passed

    def run_mock_integration_tests(self) -> bool:
        """Run mock integration tests (mirrors integration-test job)"""
        self.log("\n🔗 Mock Integration Tests", Colors.PURPLE)

        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "tests/integration/test_api_endpoints.py",
            "--junitxml=mock-integration-junit.xml",
            "-v",
        ]

        success, _ = self.run_command(cmd, "Mock integration tests")
        self.results["Mock integration tests"] = success
        return success

    def setup_xgt_server(self) -> bool:
        """Set up XGT server for integration tests"""
        if not self.args.with_xgt:
            return True

        self.log("\n🚀 Setting up XGT server...", Colors.CYAN)

        xgt_version = self.args.xgt_version or "latest"

        # Pull XGT image
        success, _ = self.run_command(["docker", "pull", f"rocketgraph/xgt:{xgt_version}"], f"Pull XGT image ({xgt_version})")
        if not success:
            return False

        # Find available port
        for port in range(4367, 4378):
            try:
                result = subprocess.run(["netstat", "-tuln"], capture_output=True, text=True)
                if f":{port} " not in result.stdout:
                    self.xgt_port = port
                    break
            except:
                pass

        if not self.xgt_port:
            # Fallback to random port
            import random

            self.xgt_port = random.randint(5000, 5999)

        self.log(f"📍 Using XGT port: {self.xgt_port}", Colors.BLUE)

        # Start XGT container
        self.xgt_container = f"ci-test-xgt-{int(time.time())}"

        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            self.xgt_container,
            "-p",
            f"{self.xgt_port}:4367",
            f"rocketgraph/xgt:{xgt_version}",
        ]

        success, _ = self.run_command(cmd, "Start XGT container")
        if not success:
            return False

        # Wait for XGT to be ready
        self.log("⏳ Waiting for XGT server to be ready...", Colors.BLUE)
        for _attempt in range(40):  # 2 minutes timeout
            try:
                result = subprocess.run(
                    ["curl", "-f", f"http://localhost:{self.xgt_port}/health"],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    self.log("✅ XGT server is ready!", Colors.GREEN)
                    return True
            except:
                pass
            time.sleep(3)

        self.log("❌ XGT server failed to start", Colors.RED)
        self.show_xgt_logs()
        return False

    def run_xgt_integration_tests(self) -> bool:
        """Run XGT integration tests (mirrors xgt-integration-test job)"""
        if not self.args.with_xgt:
            self.log("\n⏭️  Skipping XGT integration tests (use --with-xgt to enable)", Colors.YELLOW)
            return True

        self.log("\n🧪 XGT Integration Tests", Colors.PURPLE)

        env = {
            "XGT_HOST": "localhost",
            "XGT_PORT": str(self.xgt_port),
            "XGT_USERNAME": "admin",
            "XGT_PASSWORD": "",
            "ENVIRONMENT": "testing",
        }

        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "tests/integration/test_xgt_graphs.py",
            "--junitxml=xgt-integration-junit.xml",
            "-v",
            "-s",
        ]

        success, _ = self.run_command(cmd, "XGT integration tests", env=env)
        self.results["XGT integration tests"] = success
        return success

    def show_xgt_logs(self):
        """Show XGT container logs on failure"""
        if self.xgt_container:
            self.log("📋 XGT Container Logs:", Colors.YELLOW)
            try:
                result = subprocess.run(["docker", "logs", self.xgt_container], capture_output=True, text=True)
                if result.stderr:
                    pass
            except:
                self.log("Could not retrieve XGT logs", Colors.RED)

    def cleanup_xgt(self):
        """Clean up XGT container"""
        if self.xgt_container:
            self.log("🧹 Cleaning up XGT container...", Colors.YELLOW)
            subprocess.run(["docker", "stop", self.xgt_container], capture_output=True)
            subprocess.run(["docker", "rm", self.xgt_container], capture_output=True)

    def run_security_scans(self) -> bool:
        """Run additional security scans"""
        if not self.args.security_scans:
            return True

        self.log("\n🔒 Security Scans", Colors.PURPLE)

        # Safety check for dependencies
        cmd = [sys.executable, "-m", "safety", "check", "--json"]
        success, _ = self.run_command(cmd, "Safety dependency scan")
        self.results["Safety scan"] = success

        return success

    def print_summary(self):
        """Print test results summary"""
        elapsed = time.time() - self.start_time

        self.log(f"\n{'=' * 60}", Colors.BOLD)
        self.log("📊 TEST RESULTS SUMMARY", Colors.BOLD)
        self.log(f"{'=' * 60}", Colors.BOLD)

        passed = sum(1 for result in self.results.values() if result)
        total = len(self.results)

        for test_name, result in self.results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            color = Colors.GREEN if result else Colors.RED
            self.log(f"{status} {test_name}", color)

        self.log(
            f"\n📈 Overall: {passed}/{total} tests passed",
            Colors.GREEN if passed == total else Colors.RED,
        )
        self.log(f"⏱️  Total time: {elapsed:.1f}s", Colors.BLUE)

        if passed == total:
            self.log("\n🎉 All tests passed! Ready for CI/CD", Colors.GREEN)
            return True
        else:
            self.log(f"\n💥 {total - passed} test(s) failed", Colors.RED)
            return False

    def run_all_tests(self) -> bool:
        """Run the complete test suite"""
        self.log("🚀 Starting Local CI Test Suite", Colors.BOLD)
        self.log(f"Project: {self.project_root}", Colors.BLUE)

        try:
            # Setup phase
            if not self.check_requirements():
                return False

            if not self.setup_environment():
                return False

            # Test phases (mirrors GitHub Actions jobs)
            phases = [
                ("Code Quality", self.run_code_quality_checks),
                ("Unit Tests", self.run_unit_tests),
                ("Mock Integration", self.run_mock_integration_tests),
            ]

            # XGT setup and tests
            if self.args.with_xgt:
                if not self.setup_xgt_server():
                    return False
                phases.append(("XGT Integration", self.run_xgt_integration_tests))

            # Security scans
            if self.args.security_scans:
                phases.append(("Security Scans", self.run_security_scans))

            # Run all phases
            for phase_name, phase_func in phases:
                if not phase_func():
                    self.log(f"💥 {phase_name} phase failed", Colors.RED)
                    if self.args.fail_fast:
                        return False

            return True

        finally:
            self.cleanup_xgt()


def main():
    parser = argparse.ArgumentParser(
        description="Run the complete CI test suite locally",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Run basic test suite
  %(prog)s --with-xgt              # Include XGT integration tests
  %(prog)s --with-xgt --xgt-version 2.3.0  # Use specific XGT version
  %(prog)s --all-python-versions   # Test multiple Python versions
  %(prog)s --security-scans        # Include security scans
  %(prog)s --fail-fast             # Stop on first failure
        """,
    )

    parser.add_argument("--with-xgt", action="store_true", help="Include XGT integration tests (requires Docker)")
    parser.add_argument("--xgt-version", default="latest", help="XGT Docker image version (default: latest)")
    parser.add_argument(
        "--all-python-versions",
        action="store_true",
        help="Test against multiple Python versions if available",
    )
    parser.add_argument("--security-scans", action="store_true", help="Include additional security scans")
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first test failure")

    args = parser.parse_args()

    runner = TestRunner(args)
    success = runner.run_all_tests()
    runner.print_summary()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
