import { apiInitializer } from "discourse/lib/api";
import { ajax } from "discourse/lib/ajax";

const STORAGE_PREFIX = "account-security-session-observation";
const INTERVAL_MS = 24 * 60 * 60 * 1000;
let requestPending = false;

function safeRead(key) {
  try {
    return window.localStorage?.getItem(key);
  } catch {
    return null;
  }
}

function safeWrite(key, value) {
  try {
    window.localStorage?.setItem(key, value);
  } catch {
    // Storage can be unavailable in private/restricted browser contexts.
  }
}

export default apiInitializer("0.11.1", (api) => {
  async function observeIfDue() {
    const user = api.getCurrentUser();
    if (!user?.id || requestPending) {
      return;
    }

    const now = Date.now();
    const userKey = `${STORAGE_PREFIX}:user:${user.id}`;
    const lastObserved = Number(safeRead(userKey) || 0);
    const lastUserId = Number(safeRead(`${STORAGE_PREFIX}:last-user`) || 0);
    const switchedUser = lastUserId > 0 && lastUserId !== Number(user.id);

    if (!switchedUser && lastObserved > 0 && now - lastObserved < INTERVAL_MS) {
      safeWrite(`${STORAGE_PREFIX}:last-user`, String(user.id));
      return;
    }

    requestPending = true;
    try {
      await ajax("/account-security/session-observation.json", { type: "POST" });
      safeWrite(userKey, String(now));
      safeWrite(`${STORAGE_PREFIX}:last-user`, String(user.id));
    } catch {
      // This is background evidence collection only. Never interrupt normal use.
    } finally {
      requestPending = false;
    }
  }

  api.onPageChange(() => {
    void observeIfDue();
  });
});
