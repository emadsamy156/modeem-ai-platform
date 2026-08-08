"use client";

import { useState } from "react";
import { useAuth } from "@/components/auth-provider";
import { useLocale } from "@/components/locale-provider";

export default function LoginPage() {
  const { login } = useAuth();
  const { t, toggleLocale } = useLocale();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email.trim() || !password) {
      setError(t("requiredFields"));
      return;
    }
    setSubmitting(true);
    try {
      const res = await login(email.trim(), password);
      if (!res.ok) {
        setError(res.status === 401 ? t("loginFailed") : t("loginError"));
      }
    } catch {
      setError(t("loginError"));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen w-full items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="text-2xl font-bold text-emerald-400">{t("appName")}</div>
          <div className="mt-1 text-sm text-slate-400">{t("tagline")}</div>
        </div>
        <form
          onSubmit={onSubmit}
          className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-lg"
        >
          <h1 className="text-lg font-semibold text-white">{t("loginTitle")}</h1>
          <p className="mt-1 text-sm text-slate-400">{t("loginSubtitle")}</p>

          <label className="mt-6 block text-sm text-slate-300" htmlFor="email">
            {t("email")}
          </label>
          <input
            id="email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-emerald-500"
            dir="ltr"
          />

          <label className="mt-4 block text-sm text-slate-300" htmlFor="password">
            {t("password")}
          </label>
          <input
            id="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white outline-none focus:border-emerald-500"
            dir="ltr"
          />

          <div className="mt-3 min-h-5 text-sm text-red-400" role="alert">
            {error}
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="mt-2 w-full rounded-md bg-emerald-500 px-4 py-2 text-sm font-medium text-slate-950 transition-colors hover:bg-emerald-400 disabled:opacity-60"
          >
            {submitting ? t("signingIn") : t("signIn")}
          </button>
        </form>
        <div className="mt-4 text-center">
          <button
            onClick={toggleLocale}
            className="text-sm text-slate-400 underline-offset-4 hover:text-slate-200 hover:underline"
          >
            {t("language")}
          </button>
        </div>
      </div>
    </main>
  );
}
