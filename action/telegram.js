// actions/telegram.js
'use server';

import { sendMessage } from '../services/telegram';

/**
 * Sends a Telegram message to the team group about a GitHub push.
 * @param {string} message - The formatted push message.
 * @returns {Promise<{success: boolean, error?: string}>} - Result of the operation.
 */
export async function sendPushAlertAction(message) {
  try {
    if (!message) {
      throw new Error('Message is required');
    }
    const result = await sendMessage(message);
    if (!result.success) {
      throw new Error(result.error);
    }
    return { success: true };
  } catch (error) {
    console.error('Error in sendPushAlertAction:', error);
    return { success: false, error: error.message };
  }
}