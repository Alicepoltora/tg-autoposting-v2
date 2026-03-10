import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_path="bot.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS processed_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    telegram_msg_id INTEGER,
                    channel_id INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(telegram_msg_id, channel_id)
                )
            """)
            conn.commit()

    def is_processed(self, msg_id, channel_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM processed_messages WHERE telegram_msg_id = ? AND channel_id = ?",
                (msg_id, channel_id)
            )
            return cursor.fetchone() is not None

    def mark_as_processed(self, msg_id, channel_id):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO processed_messages (telegram_msg_id, channel_id) VALUES (?, ?)",
                    (msg_id, channel_id)
                )
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            logger.error(f"Database error: {e}")
            return False
