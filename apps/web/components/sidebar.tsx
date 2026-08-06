"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useLocale } from "@/components/locale-provider";

const items = [
  { href: "/", key: "dashboard" },
  { href: "/connections", key: "connections" },
  { href: "/workflows", key: "workflows" },
  { href: "/executions", key: "executions" },
  { href: "/audit-logs", key: "auditLogs" },
  { href: "/settings", key: "settings" },
];

export function Sidebar() {
  const { t } = useLocale();
  const pathname = usePathname();

  return (
    <aside className="w-60 shrink-0 border-e border-slate-800 bg-slate-950 p-4 flex flex-col gap-1">
      <div className="mb-6 px-2">
        <div className="text-lg font-bold text-emerald-400">{t("appName")}</div>
        <div className="text-xs text-slate-400 mt-1">{t("tagline")}</div>
      </div>
      {items.map((item) => {
        const active = pathname === item.href;
        return (
          <Link
            key={item.href}
            href={item.href}
            className={`rounded-md px-3 py-2 text-sm transition-colors ${
              active
                ? "bg-emerald-500/15 text-emerald-300 font-medium"
                : "text-slate-300 hover:bg-slate-800/60 hover:text-white"
            }`}
          >
            {t(item.key)}
          </Link>
        );
      })}
      <div className="mt-auto px-2 text-[11px] text-slate-500">{t("foundationPhase")} · v0.1.0</div>
    </aside>
  );
}
