// components/common/TelegramToggle.js
'use client';

import { sendPushAlertAction } from '@/action/telegram';
import { useState } from 'react';


/**
 * Toggles Telegram notifications for the user.
 * @returns {JSX.Element} - The toggle component.
 */
export default function TelegramToggle() {
  const [enabled, setEnabled] = useState(false);

  const handleToggle = async () => {
    const newState = !enabled;
    const result = await sendPushAlertAction(newState);
    if (result.success) {
      setEnabled(newState);
    } else {
      console.error('Toggle error:', result.error);
    }
  };

  return (
    <div className="p-2 border rounded flex items-center gap-2">
      <input
        type="checkbox"
        checked={enabled}
        onChange={handleToggle}
        className="h-4 w-4"
      />
      <label className="text-sm">Enable Telegram Alerts</label>
    </div>
  );
}