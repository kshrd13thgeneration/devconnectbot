// app/api/webhook/github/route.js
import { sendPushAlertAction } from '@/action/telegram';
import { handlePushEvent, verifyWebhook } from '@/services/github-webhook';


/**
 * Handles GitHub webhook POST requests for push events.
 * @param {Request} req - The incoming request.
 * @returns {Response} - HTTP response.
 */
export async function POST(req) {
  try {
    // Verify webhook signature
    const signature = req.headers.get('x-hub-signature-256');
    const payload = await req.json();
    if (!signature || !verifyWebhook(payload, signature)) {
      return new Response('Invalid signature', { status: 401 });
    }

    // Check event type
    const event = req.headers.get('x-github-event');
    if (event !== 'push') {
      return new Response('Ignored event', { status: 200 });
    }

    // Process push event
    const message = handlePushEvent(payload);
    const result = await sendPushAlertAction(message);
    if (!result.success) {
      throw new Error(result.error);
    }

    return new Response('OK', { status: 200 });
  } catch (error) {
    console.error('Webhook error:', error);
    return new Response('Server error', { status: 500 });
  }
}