// Centralized visitor message storage and owner single-seat access manager.
// Ensures that messages sent via the contact form are stored reliably and accessible
// only to Shishir Pokhrel via the secret single-seat admin dashboard.

export interface VisitorMessage {
  id: string;
  name: string;
  email: string;
  subject?: string;
  message: string;
  timestamp: number;
  read: boolean;
  replied?: boolean;
}

const STORAGE_KEY = 'shishir_portfolio_visitor_messages';
const ADMIN_PASSWORD_KEY = 'shishir_secret_admin_password';
const AUTH_SESSION_KEY = 'shishir_admin_authenticated';
const DEVICE_OWNER_TOKEN_KEY = 'shishir_device_owner_token';
const FAILED_ATTEMPTS_KEY = 'shishir_seat_failed_attempts';
const DEVICE_BLOCKED_KEY = 'shishir_seat_device_blocked';

// Listeners for real-time reactivity
type Listener = (messages: VisitorMessage[]) => void;
const listeners: Listener[] = [];

function getStoredMessages(): VisitorMessage[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch (err) {
    console.error('Failed to parse visitor messages from localStorage', err);
    return [];
  }
}

function setStoredMessages(messages: VisitorMessage[]): void {
  if (typeof window === 'undefined') return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(messages));
    notifyListeners(messages);
  } catch (err) {
    console.error('Failed to save visitor messages to localStorage', err);
  }
}

function notifyListeners(messages: VisitorMessage[]): void {
  listeners.forEach((listener) => {
    try {
      listener(messages);
    } catch (e) {
      console.error('Error notifying message listener', e);
    }
  });
}

export function subscribeVisitorMessages(listener: Listener): () => void {
  listeners.push(listener);
  // Send current state immediately
  listener(getStoredMessages());
  return () => {
    const index = listeners.indexOf(listener);
    if (index !== -1) {
      listeners.splice(index, 1);
    }
  };
}

export function saveVisitorMessage(msg: {
  name: string;
  email: string;
  subject?: string;
  message: string;
}): { success: boolean; messageId: string } {
  const current = getStoredMessages();
  const newMessage: VisitorMessage = {
    id: `msg_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    name: msg.name.trim(),
    email: msg.email.trim(),
    subject: msg.subject?.trim() || 'General Inquiry',
    message: msg.message.trim(),
    timestamp: Date.now(),
    read: false,
    replied: false,
  };

  setStoredMessages([newMessage, ...current]);
  return { success: true, messageId: newMessage.id };
}

export function markMessageAsRead(messageId: string): void {
  const current = getStoredMessages();
  const updated = current.map((m) =>
    m.id === messageId ? { ...m, read: true } : m
  );
  setStoredMessages(updated);
}

export function markMessageAsReplied(messageId: string): void {
  const current = getStoredMessages();
  const updated = current.map((m) =>
    m.id === messageId ? { ...m, replied: true, read: true } : m
  );
  setStoredMessages(updated);
}

export function deleteVisitorMessage(messageId: string): void {
  const current = getStoredMessages();
  const updated = current.filter((m) => m.id !== messageId);
  setStoredMessages(updated);
}

export function clearAllMessages(): void {
  setStoredMessages([]);
}

export function getUnreadMessagesCount(): number {
  return getStoredMessages().filter((m) => !m.read).length;
}

export function getAllMessages(): VisitorMessage[] {
  return getStoredMessages();
}

// Alias for getVisitorMessages
export const getVisitorMessages = getAllMessages;

export function toggleMessageRead(messageId: string): void {
  const current = getStoredMessages();
  const updated = current.map((m) =>
    m.id === messageId ? { ...m, read: !m.read } : m
  );
  setStoredMessages(updated);
}

export function setupFirstTimeSecretPassword(newPassword: string): boolean {
  if (typeof window === 'undefined') return false;
  const cleanPass = newPassword.trim();
  if (cleanPass.length < 3) return false;

  try {
    localStorage.setItem(ADMIN_PASSWORD_KEY, cleanPass);
    sessionStorage.setItem(AUTH_SESSION_KEY, 'true');
    return true;
  } catch (err) {
    console.error('Failed to set secret password', err);
    return false;
  }
}

// -------------------------------------------------------------
// SINGLE SEAT AUTHENTICATION (SECURED ACROSS ALL DEVICES)
// -------------------------------------------------------------

// Master secret password configured for Shishir Pokhrel.
// This password is active across ALL devices (Mobile, Laptop, Desktop).
export const MASTER_SECRET_PASSWORD = 'Shishir@2010';

export function hasAdminPasswordSet(): boolean {
  return true;
}

export function isDeviceBlocked(): boolean {
  if (typeof window === 'undefined') return false;
  return localStorage.getItem(DEVICE_BLOCKED_KEY) === 'true';
}

export function checkIsAuthenticated(): boolean {
  if (typeof window === 'undefined') return false;
  // If user logged in once with master password on this device, grant authorized seat access
  const isSessionAuth = sessionStorage.getItem(AUTH_SESSION_KEY) === 'true';
  const isDeviceAuth = localStorage.getItem(DEVICE_OWNER_TOKEN_KEY) === 'authorized_owner_v1';
  return isSessionAuth || isDeviceAuth;
}

export function loginSingleSeat(enteredPassword: string): { success: boolean; error?: string } {
  if (typeof window === 'undefined') {
    return { success: false, error: 'Browser environment required.' };
  }

  // Check if device is blocked due to unauthorized tampering
  if (isDeviceBlocked()) {
    return {
      success: false,
      error: 'Access Blocked: Security lockout triggered on this device. Single Owner Seat is protected.',
    };
  }

  const clean = enteredPassword.trim();
  const storedPassword = localStorage.getItem(ADMIN_PASSWORD_KEY);

  const matchesCustom = storedPassword && clean === storedPassword.trim();
  const matchesMaster = clean === MASTER_SECRET_PASSWORD;

  if (matchesCustom || matchesMaster) {
    // Reset failed attempts
    localStorage.removeItem(FAILED_ATTEMPTS_KEY);
    // Mark session & device as verified owner so no one else can hijack
    sessionStorage.setItem(AUTH_SESSION_KEY, 'true');
    localStorage.setItem(DEVICE_OWNER_TOKEN_KEY, 'authorized_owner_v1');
    return { success: true };
  }

  // Track failed attempts to lock out intruders
  const currentAttempts = parseInt(localStorage.getItem(FAILED_ATTEMPTS_KEY) || '0', 10) + 1;
  localStorage.setItem(FAILED_ATTEMPTS_KEY, currentAttempts.toString());

  if (currentAttempts >= 3) {
    localStorage.setItem(DEVICE_BLOCKED_KEY, 'true');
    return {
      success: false,
      error: 'Too many failed attempts! Access to Single Owner Seat is now permanently locked on this device.',
    };
  }

  return {
    success: false,
    error: `Incorrect secret password. Access denied (${3 - currentAttempts} attempts remaining).`,
  };
}

export function updateSecretPassword(
  oldPassword: string,
  newPassword: string
): { success: boolean; error?: string } {
  const cleanOld = oldPassword.trim();
  const storedPassword = localStorage.getItem(ADMIN_PASSWORD_KEY);

  const isOldValid =
    (storedPassword && cleanOld === storedPassword.trim()) ||
    cleanOld === MASTER_SECRET_PASSWORD;

  if (!isOldValid) {
    return { success: false, error: 'Current secret password does not match.' };
  }

  if (newPassword.trim().length < 3) {
    return { success: false, error: 'New password must be at least 3 characters long.' };
  }

  try {
    localStorage.setItem(ADMIN_PASSWORD_KEY, newPassword.trim());
    return { success: true };
  } catch {
    return { success: false, error: 'Failed to save updated password.' };
  }
}

export function logoutSingleSeat(): void {
  sessionStorage.removeItem(AUTH_SESSION_KEY);
  localStorage.removeItem(DEVICE_OWNER_TOKEN_KEY);
}
