"use client";

import { useLocale } from "@/components/locale-provider";

export function Header({ titleKey }: { titleKey: string }) {
  const { t, toggleLocale } = useLocale();

  return (
    <header className="flex items-center justify-between border-b border-slate-800 bg-slate-900/60 px-6 py-4">
      <h1 className="text-xl font-semibold text-white">{t(titleKey)}</h1>
      <button
        onClick={toggleLocale}
        className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800 transition-colors"
      >
        {t("language")}
      </button>
    </header>
  );
}
