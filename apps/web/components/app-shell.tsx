"use client";

import { usePathname } from "next/navigation";
import { useAuth } from "@/components/auth-provider";
import { useLocale } from "@/components/locale-provider";
import { Sidebar } from "@/components/sidebar";

/**
 * Renders the authenticated shell (sidebar + content) for app pages and a
 * bare layout for the login page. Blocks page content until the session is
 * verified so protected pages never flash for unauthenticated visitors.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { user, loading } = useAuth();
  const { t } = useLocale();

  if (pathname === "/login") {
    return <>{children}</>;
  }

  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center text-slate-400">
        {t("loading")}
      </div>
    );
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      {children}
    </div>
  );
}
