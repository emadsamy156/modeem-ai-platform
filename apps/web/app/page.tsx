"use client";

import { Header } from "@/components/header";
import { useLocale } from "@/components/locale-provider";

const demoCards = [
  { key: "activeWorkflows", value: "12", accent: "text-emerald-400" },
  { key: "successfulExecutions", value: "348", accent: "text-sky-400" },
  { key: "failedExecutions", value: "7", accent: "text-rose-400" },
  { key: "connectedSystems", value: "3", accent: "text-amber-400" },
];

export default function DashboardPage() {
  const { t } = useLocale();

  return (
    <div className="flex-1 flex flex-col">
      <Header titleKey="dashboard" />
      <main className="flex-1 p-6">
        <div className="mb-4 inline-block rounded-full border border-amber-500/40 bg-amber-500/10 px-3 py-1 text-xs text-amber-300">
          {t("demoData")}
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {demoCards.map((card) => (
            <div
              key={card.key}
              className="rounded-lg border border-slate-800 bg-slate-900/60 p-5"
            >
              <div className="text-sm text-slate-400">{t(card.key)}</div>
              <div className={`mt-2 text-3xl font-bold ${card.accent}`}>{card.value}</div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
