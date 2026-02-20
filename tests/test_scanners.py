#!/usr/bin/env python3
"""
Test suite: Scanner module import and instantiation.

Verifies that all 17 scanner modules (+ BaseScanner) can be imported
and that concrete scanners can be instantiated without errors.
This catches import-time crashes, missing dependencies on the import
path, and broken __init__ logic.
"""

import sys
import unittest
from pathlib import Path

# Ensure project root is on the path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(_PROJECT_ROOT / 'scanners'))
sys.path.insert(0, str(_PROJECT_ROOT))


class TestScannerImports(unittest.TestCase):
    """Verify every scanner module imports and the class exists."""

    def test_base_scanner(self):
        from scanners.base import BaseScanner
        self.assertTrue(hasattr(BaseScanner, 'scan'))

    def test_network_scanner(self):
        from scanners.network_scanner import NetworkScanner
        self.assertTrue(issubclass(NetworkScanner, self._base()))

    def test_vulnerability_scanner(self):
        from scanners.vulnerability_scanner import VulnerabilityScanner
        self.assertTrue(issubclass(VulnerabilityScanner, self._base()))

    def test_web_scanner(self):
        from scanners.web_scanner import WebScanner
        self.assertTrue(issubclass(WebScanner, self._base()))

    def test_ssl_scanner(self):
        from scanners.ssl_scanner import SSLScanner
        self.assertTrue(issubclass(SSLScanner, self._base()))

    def test_cloud_scanner(self):
        from scanners.cloud_scanner import CloudScanner
        self.assertTrue(issubclass(CloudScanner, self._base()))

    def test_container_scanner(self):
        from scanners.container_scanner import ContainerScanner
        self.assertTrue(issubclass(ContainerScanner, self._base()))

    def test_compliance_scanner(self):
        from scanners.compliance_scanner import ComplianceScanner
        self.assertTrue(issubclass(ComplianceScanner, self._base()))

    def test_credential_scanner(self):
        from scanners.credential_scanner import CredentialScanner
        self.assertTrue(issubclass(CredentialScanner, self._base()))

    def test_malware_scanner(self):
        from scanners.malware_scanner import MalwareScanner
        self.assertTrue(issubclass(MalwareScanner, self._base()))

    def test_shadow_ai_scanner(self):
        from scanners.shadow_ai_scanner import ShadowAIScanner
        self.assertTrue(issubclass(ShadowAIScanner, self._base()))

    def test_adversary_scanner(self):
        from scanners.adversary_scanner import AdversaryScanner
        self.assertTrue(issubclass(AdversaryScanner, self._base()))

    def test_asm_scanner(self):
        from scanners.asm_scanner import ASMScanner
        self.assertTrue(issubclass(ASMScanner, self._base()))

    def test_ad_scanner(self):
        from scanners.ad_scanner import ADScanner
        self.assertTrue(issubclass(ADScanner, self._base()))

    def test_windows_scanner(self):
        from scanners.windows_scanner import WindowsScanner
        self.assertTrue(issubclass(WindowsScanner, self._base()))

    def test_linux_scanner(self):
        from scanners.linux_scanner import LinuxScanner
        self.assertTrue(issubclass(LinuxScanner, self._base()))

    def test_sbom_scanner(self):
        from scanners.sbom_scanner import SBOMScanner
        self.assertTrue(issubclass(SBOMScanner, self._base()))

    def test_openvas_scanner(self):
        from scanners.openvas_scanner import OpenVASScanner
        self.assertTrue(issubclass(OpenVASScanner, self._base()))

    @staticmethod
    def _base():
        from scanners.base import BaseScanner
        return BaseScanner


class TestScannerInstantiation(unittest.TestCase):
    """Verify concrete scanners can be instantiated."""

    def test_instantiate_network(self):
        from scanners.network_scanner import NetworkScanner
        s = NetworkScanner()
        self.assertEqual(s.SCANNER_NAME, 'network')

    def test_instantiate_vulnerability(self):
        from scanners.vulnerability_scanner import VulnerabilityScanner
        s = VulnerabilityScanner()
        self.assertEqual(s.SCANNER_NAME, 'vulnerability')

    def test_instantiate_web(self):
        from scanners.web_scanner import WebScanner
        s = WebScanner()
        self.assertEqual(s.SCANNER_NAME, 'web')

    def test_instantiate_ssl(self):
        from scanners.ssl_scanner import SSLScanner
        s = SSLScanner()
        self.assertEqual(s.SCANNER_NAME, 'ssl')

    def test_instantiate_credential(self):
        from scanners.credential_scanner import CredentialScanner
        s = CredentialScanner()
        self.assertEqual(s.SCANNER_NAME, 'credential')

    def test_instantiate_compliance(self):
        from scanners.compliance_scanner import ComplianceScanner
        s = ComplianceScanner()
        self.assertEqual(s.SCANNER_NAME, 'compliance')

    def test_instantiate_cloud(self):
        from scanners.cloud_scanner import CloudScanner
        s = CloudScanner()
        self.assertEqual(s.SCANNER_NAME, 'cloud')

    def test_instantiate_container(self):
        from scanners.container_scanner import ContainerScanner
        s = ContainerScanner()
        self.assertEqual(s.SCANNER_NAME, 'container')

    def test_instantiate_malware(self):
        from scanners.malware_scanner import MalwareScanner
        s = MalwareScanner()
        self.assertEqual(s.SCANNER_NAME, 'malware')

    def test_instantiate_shadow_ai(self):
        from scanners.shadow_ai_scanner import ShadowAIScanner
        s = ShadowAIScanner()
        self.assertEqual(s.SCANNER_NAME, 'shadow_ai')

    def test_instantiate_adversary(self):
        from scanners.adversary_scanner import AdversaryScanner
        s = AdversaryScanner()
        self.assertEqual(s.SCANNER_NAME, 'adversary')

    def test_instantiate_asm(self):
        from scanners.asm_scanner import ASMScanner
        s = ASMScanner()
        self.assertEqual(s.SCANNER_NAME, 'asm')

    def test_instantiate_ad(self):
        from scanners.ad_scanner import ADScanner
        s = ADScanner()
        self.assertEqual(s.SCANNER_NAME, 'activedirectory')

    def test_instantiate_windows(self):
        from scanners.windows_scanner import WindowsScanner
        s = WindowsScanner()
        self.assertEqual(s.SCANNER_NAME, 'windows')

    def test_instantiate_linux(self):
        from scanners.linux_scanner import LinuxScanner
        s = LinuxScanner()
        self.assertEqual(s.SCANNER_NAME, 'linux')

    def test_instantiate_sbom(self):
        from scanners.sbom_scanner import SBOMScanner
        s = SBOMScanner()
        self.assertEqual(s.SCANNER_NAME, 'sbom')

    def test_instantiate_openvas(self):
        from scanners.openvas_scanner import OpenVASScanner
        s = OpenVASScanner()
        self.assertEqual(s.SCANNER_NAME, 'openvas')


if __name__ == '__main__':
    unittest.main()
