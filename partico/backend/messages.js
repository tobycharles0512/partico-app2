// Pure, dependency-free helpers for host<->guest chat.
// Kept separate from server.js so the logic is unit-testable without Supabase.

const uid = () =>
  Math.random().toString(36).slice(2) + Date.now().toString(36);

function validateMessageText(text) {
  return typeof text === 'string' && text.trim().length > 0;
}

function buildMessage({ from, text }) {
  return {
    id: uid(),
    from,
    text: text.trim(),
    timestamp: Date.now(),
    readBy: [from],
  };
}

function appendMessage(thread, msg) {
  return [...(thread || []), msg];
}

function buildMessageNotif({ partyId, guestId, from, text }) {
  return {
    id: uid(),
    type: 'message',
    partyId,
    guestId,
    from,
    preview: text.trim().slice(0, 60),
    timestamp: Date.now(),
    read: false,
  };
}

module.exports = {
  uid,
  validateMessageText,
  buildMessage,
  appendMessage,
  buildMessageNotif,
};
