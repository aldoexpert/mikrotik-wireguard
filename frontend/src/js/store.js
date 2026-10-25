import { createStore } from 'framework7';

const STORAGE_KEY = 'mtwg.session';

function loadSession() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

function persistSession(session) {
  try {
    if (session) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch (e) {
    // localStorage unavailable (private mode, etc.) -- session just won't survive a reload
  }
}

const initialSession = loadSession();

const store = createStore({
  state: {
    session: initialSession, // { token, username, admin } | null
  },
  getters: {
    session({ state }) {
      return state.session;
    },
    isLoggedIn({ state }) {
      return !!(state.session && state.session.token);
    },
    isAdmin({ state }) {
      return !!(state.session && state.session.admin);
    },
    token({ state }) {
      return state.session ? state.session.token : null;
    },
  },
  actions: {
    setSession({ state }, session) {
      state.session = session;
      persistSession(session);
    },
    clearSession({ state }) {
      state.session = null;
      persistSession(null);
    },
  },
});

export default store;
