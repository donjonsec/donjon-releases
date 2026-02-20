#!/usr/bin/env python3
"""
Test suite: EULA acceptance flows.

Verifies the Phase 1 fix: empty Enter re-prompts instead of
silently declining, bare input() replaced with safe_input(),
and non-interactive mode works via DONJON_ACCEPT_EULA env var.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure project root is on the path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(_PROJECT_ROOT))


class TestEulaModule(unittest.TestCase):
    """Test EULA module functions."""

    def test_get_eula_summary(self):
        from lib.eula import get_eula_summary, EULA_VERSION
        summary = get_eula_summary()
        self.assertIn(EULA_VERSION, summary)
        self.assertIn('EULA', summary)

    def test_get_machine_id_stable(self):
        from lib.eula import _get_machine_id
        id1 = _get_machine_id()
        id2 = _get_machine_id()
        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 16)

    def test_record_and_check_acceptance(self):
        """Test that recording acceptance creates a valid file."""
        from lib.eula import record_acceptance, EULA_VERSION
        with tempfile.TemporaryDirectory() as tmpdir:
            # Temporarily override the acceptance file path
            from lib import eula
            original_file = eula._ACCEPTANCE_FILE
            eula._ACCEPTANCE_FILE = Path(tmpdir) / "eula_accepted.json"
            try:
                record = record_acceptance()
                self.assertEqual(record['eula_version'], EULA_VERSION)
                self.assertIn('accepted_at', record)
                self.assertIn('machine_id', record)

                # Verify the file was written
                data = json.loads(eula._ACCEPTANCE_FILE.read_text('utf-8'))
                self.assertEqual(data['eula_version'], EULA_VERSION)
            finally:
                eula._ACCEPTANCE_FILE = original_file

    def test_env_accepted(self):
        """Test DONJON_ACCEPT_EULA env var."""
        from lib.eula import _env_accepted
        with patch.dict(os.environ, {'DONJON_ACCEPT_EULA': 'yes'}):
            self.assertTrue(_env_accepted())
        with patch.dict(os.environ, {'DONJON_ACCEPT_EULA': ''}):
            self.assertFalse(_env_accepted())
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(_env_accepted())

    def test_empty_input_not_in_decline_set(self):
        """Verify the Phase 1 fix: empty string is NOT in the decline set.

        The original bug had '' in ('n', 'no', '') which silently declined
        when users pressed Enter. After the fix, empty input re-prompts.
        """
        import inspect
        from lib.eula import prompt_eula_acceptance_tui
        source = inspect.getsource(prompt_eula_acceptance_tui)
        # Ensure the decline set does NOT contain empty string
        self.assertNotIn('("n", "no", "")', source)
        # Ensure empty input handling exists
        self.assertIn('response == ""', source)

    def test_page_text_uses_safe_input(self):
        """Verify the Phase 1 fix: _page_text uses safe_input, not bare input()."""
        import inspect
        from lib.eula import _page_text
        source = inspect.getsource(_page_text)
        self.assertIn('safe_input', source)
        # Should not have bare input() (the old code)
        # Check that 'input(' doesn't appear outside of 'safe_input('
        lines = source.split('\n')
        for line in lines:
            stripped = line.strip()
            if 'input(' in stripped and 'safe_input' not in stripped and not stripped.startswith('#'):
                self.fail(f"Found bare input() in _page_text: {stripped}")


if __name__ == '__main__':
    unittest.main()
