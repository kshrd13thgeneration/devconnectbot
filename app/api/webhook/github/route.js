// // app/api/webhook/github/route.js
// import { sendPushAlertAction } from '@/action/telegram';
// import { handlePushEvent, verifyWebhook } from '@/services/github-webhook';


// /**
//  * Handles GitHub webhook POST requests for push events.
//  * @param {Request} req - The incoming request.
//  * @returns {Response} - HTTP response.
//  */
// export async function POST(req) {
//   try {
//     // Verify webhook signature
//     const signature = req.headers.get('x-hub-signature-256');
//     const payload = await req.json();
//     if (!signature || !verifyWebhook(payload, signature)) {
//       return new Response('Invalid signature', { status: 401 });
//     }

//     // Check event type
//     const event = req.headers.get('x-github-event');
//     if (event !== 'push') {
//       return new Response('Ignored event', { status: 200 });
//     }

//     // Process push event
//     const message = handlePushEvent(payload);
//     const result = await sendPushAlertAction(message);
//     if (!result.success) {
//       throw new Error(result.error);
//     }

//     return new Response('OK', { status: 200 });
//   } catch (error) {
//     console.error('Webhook error:', error);
//     return new Response('Server error', { status: 500 });
//   }
// }


import crypto from 'crypto';
import { sendPushAlertAction } from '@/action/telegram';
import { handlePushEvent } from '@/services/github-webhook';

/**
 * Verify the GitHub webhook signature using the raw body and secret.
 * @param {string} rawBody - The raw request body as a string.
 * @param {string} signature - The signature from the `x-hub-signature-256` header.
 * @returns {boolean} True if signature is valid.
 */
function verifyWebhook(rawBody, signature) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    console.error('GITHUB_WEBHOOK_SECRET is not set');
    return false;
  }

  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(rawBody, 'utf-8');
  const digest = `sha256=${hmac.digest('hex')}`;

  try {
    // timingSafeEqual requires Buffers of same length
    const sigBuffer = Buffer.from(signature);
    const digestBuffer = Buffer.from(digest);

    if (sigBuffer.length !== digestBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(sigBuffer, digestBuffer);
  } catch {
    return false;
  }
}

export async function POST(req) {
  try {
    const signature = req.headers.get('x-hub-signature-256');
    const rawBody = await req.text(); // Get raw body as string

    // Verify signature
    if (!signature || !verifyWebhook(rawBody, signature)) {
      return new Response('Invalid signature', { status: 401 });
    }

    const payload = JSON.parse(rawBody);
    const event = req.headers.get('x-github-event');

    if (event !== 'push') {
      return new Response('Ignored event', { status: 200 });
    }

    // Process push event and send Telegram alert
    const message = handlePushEvent(payload);
    const result = await sendPushAlertAction(message);

    if (!result.success) {
      throw new Error(result.error || 'Failed to send Telegram alert');
    }

    return new Response('OK', { status: 200 });
  } catch (error) {
    console.error('Webhook error:', error);
    return new Response('Internal Server Error', { status: 500 });
  }
}
