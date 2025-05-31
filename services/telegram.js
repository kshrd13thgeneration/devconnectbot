// services/telegram.js
import TelegramBot from 'node-telegram-bot-api';
import { TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID } from '../lib/constants';

/**
 * Initializes Telegram bot (singleton to avoid multiple instances).
 */
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: false });

/**
 * Sends a message to the configured Telegram group.
 * @param {string} text - The message to send.
 * @returns {Promise<{success: boolean, error?: string}>}
 */
export async function sendMessage(text) {
  try {
    if (!text || typeof text !== 'string') {
      throw new Error('Invalid message text');
    }
    await bot.sendMessage(TELEGRAM_CHAT_ID, text, { parse_mode: 'Markdown' });
    return { success: true };
  } catch (error) {
    console.error('Telegram API error:', error);
    return { success: false, error: error.message };
  }
}