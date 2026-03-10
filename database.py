import sqlite3
import logging
from datetime import datetime, timedelta

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

    def get_stats(self, hours=24):
        """Get statistics for the last N hours"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Calculate time threshold
                since = datetime.now() - timedelta(hours=hours)
                
                # Messages processed in period
                cursor.execute(
                    "SELECT COUNT(*) FROM processed_messages WHERE timestamp > ?",
                    (since.isoformat(),)
                )
                processed_in_period = cursor.fetchone()[0]
                
                # Total messages ever processed
                cursor.execute("SELECT COUNT(*) FROM processed_messages")
                total_processed = cursor.fetchone()[0]
                
                return {
                    "processed_24h": processed_in_period,
                    "total_processed": total_processed,
                    "period_hours": hours
                }
        except Exception as e:
            logger.error(f"Stats error: {e}")
            return {"processed_24h": 0, "total_processed": 0, "error": str(e)}

    def get_recent_messages(self, limit=10):
        """Get the most recently processed messages"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, telegram_msg_id, channel_id, timestamp FROM processed_messages ORDER BY id DESC LIMIT ?",
                    (limit,)
                )
                messages = [
                    {
                        "id": row[0],
                        "message_id": row[1],
                        "channel_id": row[2],
                        "timestamp": row[3]
                    }
                    for row in cursor.fetchall()
                ]
                return messages
        except Exception as e:
            logger.error(f"Recent messages error: {e}")
            return []

    def get_messages_by_channel(self, channel_id):
        """Get count of messages processed from a specific channel"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM processed_messages WHERE channel_id = ?",
                    (channel_id,)
                )
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Channel stats error: {e}")
            return 0
