export type Locale = "en" | "ar";

export const dictionaries: Record<Locale, Record<string, string>> = {
  en: {
    appName: "Modeem AI Platform",
    tagline: "Business automation & AI workflows",
    dashboard: "Dashboard",
    connections: "Connections",
    workflows: "Workflows",
    executions: "Executions",
    auditLogs: "Audit Logs",
    settings: "Settings",
    activeWorkflows: "Active workflows",
    successfulExecutions: "Successful executions",
    failedExecutions: "Failed executions",
    connectedSystems: "Connected systems",
    demoData: "Demonstration data — not real",
    comingSoon: "This section will be implemented in a later phase.",
    language: "العربية",
    foundationPhase: "Foundation phase",
  },
  ar: {
    appName: "منصة مديم للذكاء الاصطناعي",
    tagline: "أتمتة الأعمال وسير عمل الذكاء الاصطناعي",
    dashboard: "لوحة التحكم",
    connections: "الاتصالات",
    workflows: "سير العمل",
    executions: "عمليات التنفيذ",
    auditLogs: "سجلات التدقيق",
    settings: "الإعدادات",
    activeWorkflows: "سير العمل النشطة",
    successfulExecutions: "عمليات تنفيذ ناجحة",
    failedExecutions: "عمليات تنفيذ فاشلة",
    connectedSystems: "الأنظمة المتصلة",
    demoData: "بيانات توضيحية — ليست حقيقية",
    comingSoon: "سيتم تنفيذ هذا القسم في مرحلة لاحقة.",
    language: "English",
    foundationPhase: "مرحلة التأسيس",
  },
};

export function dirFor(locale: Locale): "ltr" | "rtl" {
  return locale === "ar" ? "rtl" : "ltr";
}
