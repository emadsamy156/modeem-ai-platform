import type { Metadata } from "next";
import "./globals.css";
import { LocaleProvider } from "@/components/locale-provider";
import { Sidebar } from "@/components/sidebar";

export const metadata: Metadata = {
  title: "Modeem AI Platform",
  description: "Business automation and AI workflows for Odoo users",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ar" dir="rtl">
      <body className="antialiased">
        <LocaleProvider>
          <div className="flex min-h-screen">
            <Sidebar />
            {children}
          </div>
        </LocaleProvider>
      </body>
    </html>
  );
}
