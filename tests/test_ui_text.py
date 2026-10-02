import ast
import string
import unittest
from pathlib import Path

from ui_text import MESSAGES


class UiTranslationTest(unittest.TestCase):
    def test_translations_preserve_format_fields(self):
        formatter = string.Formatter()
        for english, vietnamese in MESSAGES.items():
            with self.subTest(message=english):
                fields = lambda text: {name for _, name, _, _ in formatter.parse(text) if name is not None}
                self.assertEqual(fields(english), fields(vietnamese))
                values = {name: 'fixture' for name in fields(english)}
                vietnamese.format(**values)

    def test_literal_ui_messages_have_vietnamese_translations(self):
        root = Path(__file__).resolve().parents[1]
        for filename in ['sigma_rules_menu.py', 'sigma_kibana_api.py', 'split_sigma_rules.py']:
            tree = ast.parse((root / filename).read_text())
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == 'tr' and node.args and isinstance(node.args[0], ast.Constant)):
                    with self.subTest(file=filename, message=node.args[0].value):
                        self.assertIn(node.args[0].value, MESSAGES)


if __name__ == '__main__':
    unittest.main()
