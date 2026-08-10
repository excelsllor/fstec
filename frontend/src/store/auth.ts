import { create } from "zustand";
import { authApi, type UserResponse } from "../api/client";

interface AuthState {
  user: UserResponse | null;
  token: string | null;
  isLoading: boolean;
  needsSetup: boolean;
  initialized: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;
  checkStatus: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: localStorage.getItem("fstec_token"),
  isLoading: false,
  needsSetup: false,
  initialized: false,

  login: async (username, password) => {
    const { data } = await authApi.login(username, password);
    localStorage.setItem("fstec_token", data.access_token);
    const { data: user } = await authApi.me();
    set({ token: data.access_token, user, needsSetup: false, initialized: true });
  },

  logout: () => {
    localStorage.removeItem("fstec_token");
    localStorage.removeItem("fstec_user");
    set({ user: null, token: null, initialized: false });
  },

  checkAuth: async () => {
    const token = localStorage.getItem("fstec_token");
    if (!token) {
      set({ user: null, token: null });
      return;
    }
    try {
      const { data } = await authApi.me();
      set({ user: data, token, initialized: true });
    } catch {
      localStorage.removeItem("fstec_token");
      localStorage.removeItem("fstec_user");
      set({ user: null, token: null });
    }
  },

  checkStatus: async () => {
    for (let i = 0; i < 30; i++) {
      try {
        const { data } = await authApi.status();
        set({ needsSetup: data.needs_setup, initialized: true });
        return;
      } catch {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    set({ needsSetup: false, initialized: true });
  },
}));
