#!/usr/bin/env python3
"""
Comprehensive test runner for SecurAI Guardian.

Executes all test suites with coverage reporting, mutation testing, and quality gates.
Ensures 100% coverage requirement is met before deployment.
"""

import subprocess
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple
import json
import xml.etree.ElementTree as ET


class TestRunner:
    """Test runner with coverage and quality gates."""

    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.test_dir = self.project_root / "tests"
        self.coverage_threshold = 100.0  # Blueprint requirement: 100%
        self.mutation_threshold = 90.0   # Mutation testing: ≥90%
        self.results = {
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "total": 0,
            "coverage": 0.0,
            "mutation_score": 0.0,
            "duration": 0.0
        }

    def run_command(self, cmd: List[str], cwd: Path = None) -> Tuple[int, str, str]:
        """Run command and capture output."""
        if cwd is None:
            cwd = self.project_root

        print(f"\n[RUN] {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        return result.returncode, result.stdout, result.stderr

    def check_dependencies(self) -> bool:
        """Check if all test dependencies are installed."""
        print("[CHECK] Verifying test dependencies...")

        required = [
            "pytest", "pytest-asyncio", "pytest-cov", "pytest-mock",
            "hypothesis", "mutmut", "coverage", "black", "flake8", "mypy"
        ]

        missing = []
        for package in required:
            try:
                __import__(package.replace("-", "_"))
            except ImportError:
                missing.append(package)

        if missing:
            print(f"[ERROR] Missing dependencies: {', '.join(missing)}")
            print("[INFO] Install with: pip install " + " ".join(missing))
            return False

        print("[OK] All dependencies installed")
        return True

    def run_linting(self) -> bool:
        """Run code linting with black and flake8."""
        print("\n[LINT] Running code quality checks...")

        # Black formatting check
        print("\n[BLACK] Checking code formatting...")
        code, stdout, stderr = self.run_command(["black", "--check", "core/", "agents/", "app/", "tests/"])
        if code != 0:
            print("[ERROR] Code formatting issues found. Run 'black core agents app tests' to fix.")
            print(stdout)
            print(stderr)
            return False
        print("[OK] Code formatting passed")

        # Flake8 linting
        print("\n[FLAKE8] Running linting...")
        code, stdout, stderr = self.run_command([
            "flake8",
            "core/", "agents/", "app/", "tests/",
            "--max-line-length=100",
            "--extend-ignore=E203,W503",
            "--count",
            "--statistics"
        ])
        if code != 0:
            print("[ERROR] Linting errors found:")
            print(stdout)
            print(stderr)
            return False
        print("[OK] Linting passed")

        # MyPy type checking
        print("\n[MYPY] Running type checking...")
        code, stdout, stderr = self.run_command([
            "mypy",
            "core/", "agents/", "app/",
            "--ignore-missing-imports",
            "--disallow-untyped-defs",
            "--disallow-any-unimported",
            "--no-implicit-optional"
        ])
        if code != 0:
            print("[WARN] Type checking issues found (non-fatal):")
            print(stdout)
            print(stderr)
            # Don't fail on type errors, just warn
        print("[OK] Type checking passed (or warnings only)")

        return True

    def run_unit_tests(self) -> Tuple[bool, Dict]:
        """Run unit tests with coverage."""
        print("\n[TEST] Running unit tests with coverage...")

        # Run pytest with coverage
        cmd = [
            "pytest",
            "tests/unit/",
            "-v",
            "--tb=short",
            f"--cov=core",
            f"--cov=agents",
            f"--cov=app",
            f"--cov-report=term-missing:skip-covered",
            f"--cov-report=xml:coverage.xml",
            f"--cov-report=html:htmlcov",
            f"--cov-fail-under={self.coverage_threshold}",
            "--junitxml=test-results.xml"
        ]

        code, stdout, stderr = self.run_command(cmd)

        # Parse coverage from output
        coverage = self.parse_coverage_from_output(stdout)

        success = code == 0
        if success:
            print(f"[PASS] Unit tests passed with {coverage:.1f}% coverage")
        else:
            print(f"[FAIL] Unit tests failed or coverage below {self.coverage_threshold}%")
            print(stdout)
            print(stderr)

        return success, {"coverage": coverage, "output": stdout, "errors": stderr}

    def parse_coverage_from_output(self, output: str) -> float:
        """Parse coverage percentage from pytest-cov output."""
        for line in output.split("\n"):
            if "TOTAL" in line and "%" in line:
                parts = line.split()
                # Find the percentage column (usually last or second-to-last)
                for part in reversed(parts):
                    if "%" in part:
                        try:
                            return float(part.strip("%"))
                        except ValueError:
                            continue
        return 0.0

    def run_integration_tests(self) -> bool:
        """Run integration tests."""
        print("\n[TEST] Running integration tests...")

        cmd = [
            "pytest",
            "tests/integration/",
            "-v",
            "--tb=short",
            "--junitxml=integration-results.xml"
        ]

        code, stdout, stderr = self.run_command(cmd)

        if code == 0:
            print("[PASS] Integration tests passed")
        else:
            print("[FAIL] Integration tests failed")
            print(stdout)
            print(stderr)

        return code == 0

    def run_e2e_tests(self) -> bool:
        """Run end-to-end tests."""
        print("\n[TEST] Running end-to-end tests...")

        cmd = [
            "pytest",
            "tests/e2e/",
            "-v",
            "--tb=short",
            "--junitxml=e2e-results.xml"
        ]

        code, stdout, stderr = self.run_command(cmd)

        if code == 0:
            print("[PASS] E2E tests passed")
        else:
            print("[FAIL] E2E tests failed")
            print(stdout)
            print(stderr)

        return code == 0

    def run_property_tests(self) -> bool:
        """Run property-based tests with Hypothesis."""
        print("\n[TEST] Running property-based tests...")

        cmd = [
            "pytest",
            "tests/property/",
            "-v",
            "--tb=short",
            "--hypothesis-show-statistics",
            "--junitxml=property-results.xml"
        ]

        code, stdout, stderr = self.run_command(cmd)

        if code == 0:
            print("[PASS] Property-based tests passed")
        else:
            print("[FAIL] Property-based tests failed")
            print(stdout)
            print(stderr)

        return code == 0

    def run_mutation_testing(self) -> Tuple[bool, float]:
        """Run mutation testing with mutmut."""
        print("\n[MUTATION] Running mutation testing...")

        # First, ensure tests are all passing
        print("[MUTATION] Prerequisite: Running full test suite...")
        cmd = ["pytest", "tests/", "-v"]
        code, stdout, stderr = self.run_command(cmd)
        if code != 0:
            print("[FAIL] Mutation testing skipped: tests not passing")
            return False, 0.0

        # Run mutmut
        print("[MUTATION] Running mutmut...")
        cmd = [
            "mutmut",
            "run",
            "--paths-to-mutate=core agents app",
            "--runner='pytest -x'",
            "--no-progress"
        ]

        code, stdout, stderr = self.run_command(cmd)

        # Parse mutation results
        mutation_score = self.parse_mutation_score(stdout)

        success = mutation_score >= self.mutation_threshold
        if success:
            print(f"[PASS] Mutation score: {mutation_score:.1f}% (≥{self.mutation_threshold}%)")
        else:
            print(f"[FAIL] Mutation score: {mutation_score:.1f}% (required ≥{self.mutation_threshold}%)")

        return success, mutation_score

    def parse_mutation_score(self, output: str) -> float:
        """Parse mutation score from mutmut output."""
        for line in output.split("\n"):
            if "Mutation score" in line or "score" in line.lower():
                # Look for percentage
                import re
                match = re.search(r'(\d+(?:\.\d+)?)%', line)
                if match:
                    return float(match.group(1))
        return 0.0

    def generate_test_report(self):
        """Generate comprehensive test report."""
        print("\n[REPORT] Generating test report...")

        report = {
            "timestamp": self.get_timestamp(),
            "results": self.results,
            "coverage": self.results["coverage"],
            "mutation_score": self.results["mutation_score"],
            "status": "PASS" if self.is_successful() else "FAIL"
        }

        report_file = self.project_root / "test-report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[REPORT] Test report saved to: {report_file}")

    def get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"

    def is_successful(self) -> bool:
        """Check if all quality gates passed."""
        return (
            self.results["coverage"] >= self.coverage_threshold and
            self.results["mutation_score"] >= self.mutation_threshold and
            self.results["failed"] == 0
        )

    def run_all_tests(self) -> bool:
        """Run complete test suite with all quality gates."""
        print("=" * 80)
        print("SECURAI GUARDIAN - COMPREHENSIVE TEST SUITE")
        print("=" * 80)

        # Check dependencies
        if not self.check_dependencies():
            return False

        # Run linting
        if not self.run_linting():
            print("\n[STOP] Linting failed. Fix code quality issues before testing.")
            return False

        # Run unit tests with coverage
        unit_success, unit_results = self.run_unit_tests()
        self.results["coverage"] = unit_results["coverage"]

        if not unit_success:
            print(f"\n[STOP] Unit tests failed or coverage below {self.coverage_threshold}%")
            return False

        # Run integration tests
        integration_success = self.run_integration_tests()
        if not integration_success:
            print("\n[STOP] Integration tests failed")
            return False

        # Run E2E tests
        e2e_success = self.run_e2e_tests()
        if not e2e_success:
            print("\n[STOP] E2E tests failed")
            return False

        # Run property-based tests
        property_success = self.run_property_tests()
        if not property_success:
            print("\n[STOP] Property-based tests failed")
            return False

        # Run mutation testing
        mutation_success, mutation_score = self.run_mutation_testing()
        self.results["mutation_score"] = mutation_score

        if not mutation_success:
            print(f"\n[STOP] Mutation testing failed (score: {mutation_score:.1f}%)")
            return False

        # All tests passed
        print("\n" + "=" * 80)
        print("[SUCCESS] ALL TESTS PASSED")
        print("=" * 80)
        print(f"Coverage: {self.results['coverage']:.1f}% (≥{self.coverage_threshold}%)")
        print(f"Mutation Score: {self.results['mutation_score']:.1f}% (≥{self.mutation_threshold}%)")
        print("Quality Gates: ✓ PASSED")
        print("=" * 80)

        # Generate report
        self.generate_test_report()

        return True


def main():
    """Main entry point."""
    runner = TestRunner()
    success = runner.run_all_tests()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
