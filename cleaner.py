import re

class TextCleaner:
    def __init__(self, rules=None):
        """
        rules: list of dictionaries with 'pattern' and 'replacement' keys
        """
        self.rules = rules or []

    def set_rules(self, rules):
        self.rules = rules

    def clean(self, text):
        if not text:
            return ""
        
        cleaned_text = text
        for rule in self.rules:
            pattern = rule.get("pattern")
            replacement = rule.get("replacement", "")
            if pattern:
                cleaned_text = re.sub(pattern, replacement, cleaned_text)
        
        return cleaned_text.strip()

# Default shared cleaner
default_cleaner = TextCleaner()
