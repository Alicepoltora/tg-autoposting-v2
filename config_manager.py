import json
import os

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "sources": ["@ILTVnews", "@hnaftali", "@Khabar_Fouri", "@arabiasocialism", "@PalinfoRu", "@alexavni", "@allaboutiranst"],
    "target": "@iraniumnew",
    "cleaning_rules": [
        {"pattern": r"https?://\S+", "replacement": "[LINK]"},
        {"pattern": r"@[a-zA-Z0-9_]+", "replacement": ""},
        {"pattern": r"#\w+", "replacement": ""},
        {"pattern": r"\n\s*\n", "replacement": "\n\n"}
    ],
    "auto_translate": True
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4, ensure_unicode=False)
        return DEFAULT_CONFIG
    
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_unicode=False)
