import os
import asyncio
import logging
from dotenv import load_dotenv
from telethon import TelegramClient, events
from database import Database
from cleaner import default_cleaner
from deep_translator import GoogleTranslator
from langdetect import detect, DetectorFactory
from config_manager import load_config

# Ensure langdetect gives consistent results
DetectorFactory.seed = 0

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load config
config = load_config()

# Sync cleaner rules
default_cleaner.set_rules(config.get("cleaning_rules", []))

API_ID = os.getenv("TG_API_ID")
API_HASH = os.getenv("TG_API_HASH")
SESSION_NAME = os.getenv("TG_SESSION_NAME", "bot_session")
SOURCE_CHANNELS = config.get("sources", [])
TARGET_CHANNEL = config.get("target")
AUTO_TRANSLATE = config.get("auto_translate", True)

# Initialize Telegram client
tg_client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
db = Database()

def translate_text(text):
    if not text or len(text.strip()) < 3 or not AUTO_TRANSLATE:
        return text
    try:
        # Avoid translation if text is already Russian
        lang = detect(text)
        if lang != 'ru':
            logger.info(f"Detected language: {lang}. Translating to Russian...")
            translated = GoogleTranslator(source='auto', target='ru').translate(text)
            return translated
    except Exception as e:
        logger.error(f"Translation error: {e}")
    return text

async def handle_new_message(event):
    msg = event.message
    
    # Identify channel ID for deduplication
    channel_id = 0
    if hasattr(msg.peer_id, 'channel_id'):
        channel_id = msg.peer_id.channel_id
    elif hasattr(msg.peer_id, 'chat_id'):
        channel_id = msg.peer_id.chat_id
    
    if db.is_processed(msg.id, channel_id):
        logger.info(f"Message {msg.id} in channel {channel_id} already processed. Skipping.")
        return

    # Don't process messages from the target channel itself to avoid loops
    try:
        target_entity = await tg_client.get_entity(TARGET_CHANNEL)
        # Use getattr safely for peer_id attributes
        current_id = getattr(msg.peer_id, 'channel_id', getattr(msg.peer_id, 'chat_id', None))
        if current_id == target_entity.id:
            return
    except Exception:
        pass

    logger.info(f"Processing new message {msg.id} from channel {channel_id}")
    
    # Extract and clean text
    original_text = msg.message or ""
    cleaned_text = default_cleaner.clean(original_text)
    
    # Translate if necessary
    processed_text = translate_text(cleaned_text)
    
    # Forward/Send to Target Telegram Channel
    try:
        if not TARGET_CHANNEL:
            logger.warning("TARGET_CHANNEL not set in .env. Printing processed message:")
            logger.info(f"PROCESSED TEXT: {processed_text}")
        else:
            if msg.media:
                # Send message with processed caption
                await tg_client.send_file(
                    TARGET_CHANNEL,
                    msg.media,
                    caption=processed_text
                )
            else:
                # Send text-only message
                await tg_client.send_message(
                    TARGET_CHANNEL,
                    processed_text
                )
            logger.info(f"Successfully forwarded message {msg.id} to {TARGET_CHANNEL}")
            
    except Exception as e:
        logger.error(f"Failed to send message to Telegram: {e}")

    # Mark as processed in database
    db.mark_as_processed(msg.id, channel_id)

@tg_client.on(events.NewMessage(chats=[s.strip() for s in SOURCE_CHANNELS if s.strip()]))
async def main_handler(event):
    await handle_new_message(event)

async def start_bot():
    logger.info("Starting Telegram client...")
    
    # We prioritize User authentication for monitoring public channels
    # as Bot Token often has restrictions on following message events in random channels.
    await tg_client.start()
    
    logger.info("Bot is running. Monitoring channels...")
    await tg_client.run_until_disconnected()

if __name__ == "__main__":
    if not API_ID or not API_HASH:
        logger.error("TG_API_ID and TG_API_HASH must be set in .env")
    elif not TARGET_CHANNEL:
        logger.error("TARGET_CHANNEL must be set in .env")
    else:
        asyncio.run(start_bot())
