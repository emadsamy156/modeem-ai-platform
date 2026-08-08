"use client";

import { useCallback, useEffect, useState } from "react";

import { useAuth } from "@/components/auth-provider";
import { Header } from "@/components/header";
import { useLocale } from "@/components/locale-provider";

type ConnectionOut = {
  id: string;
  name: string;
  provider: string;
  base_url: string;
  database_name: string | null;
  username: string | null;
  status: string;
  is_active: boolean;
  has_credentials: boolean;
  auth_mode: string;
  detected_odoo_version: string | null;
  detected_edition: string | null;
  selected_transport: string | null;
  last_tested_at: string | null;
  last_test_status: string | null;
  last_test_error_code: string | null;
  updated_at: string;
};

type TestResult = {
  success: boolean;
  error_code: string | null;
  odoo_version: string | null;
  edition: string | null;
  transport: string | null;
  tested_at: string;
};

function csrfHeaders(): Record<string, string> {
  const match = document.cookie.match(/(?:^|;\s*)modeem_csrf=([^;]+)/);
  return match ? { "X-CSRF-Token": decodeURIComponent(match[1]) } : {};
}

type FormState = {
  name: string;
  base_url: string;
  database_name: string;
  username: string;
  auth_mode: string;
  secret: string;
};

const emptyForm: FormState = {
  name: "",
  base_url: "",
  database_name: "",
  username: "",
  auth_mode: "auto",
  secret: "",
};

export default function ConnectionsPage() {
  const { t, locale } = useLocale();
  const { user } = useAuth();
  const role = user?.current_tenant?.role ?? "";
  const canWrite = role === "owner" || role === "admin" || role === "superuser";

  const [rows, setRows] = useState<ConnectionOut[] | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [editing, setEditing] = useState<ConnectionOut | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, TestResult>>({});

  const load = useCallback(async () => {
    try {
      const res = await fetch("/backend/api/v1/connections", { credentials: "same-origin" });
      if (!res.ok) throw new Error();
      setRows(await res.json());
      setLoadError(false);
    } catch {
      setLoadError(true);
      setRows([]);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setFormError(null);
    setShowForm(true);
  };

  const openEdit = (c: ConnectionOut) => {
    setEditing(c);
    setForm({
      name: c.name,
      base_url: c.base_url,
      database_name: c.database_name ?? "",
      username: c.username ?? "",
      auth_mode: c.auth_mode ?? "auto",
      secret: "", // never pre-fill an existing secret
    });
    setFormError(null);
    setShowForm(true);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setFormError(null);
    try {
      let res: Response;
      if (editing) {
        const body: Record<string, unknown> = {
          name: form.name,
          base_url: form.base_url,
          database_name: form.database_name || null,
          username: form.username || null,
          auth_mode: form.auth_mode,
        };
        if (form.secret) {
          body.credentials = { login: form.username || form.name, password_or_api_key: form.secret };
        }
        res = await fetch(`/backend/api/v1/connections/${editing.id}`, {
          method: "PATCH",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", ...csrfHeaders() },
          body: JSON.stringify(body),
        });
      } else {
        res = await fetch("/backend/api/v1/connections", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", ...csrfHeaders() },
          body: JSON.stringify({
            name: form.name,
            provider: "odoo",
            base_url: form.base_url,
            database_name: form.database_name || null,
            username: form.username || null,
            auth_mode: form.auth_mode,
            credentials: { login: form.username || form.name, password_or_api_key: form.secret },
          }),
        });
      }
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        setFormError(typeof data?.detail === "string" ? data.detail : t("connError"));
        return;
      }
      // Clear form state (including the secret) before closing.
      setForm(emptyForm);
      setEditing(null);
      setShowForm(false);
      await load();
    } catch {
      setFormError(t("connError"));
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async (c: ConnectionOut) => {
    setTestingId(c.id);
    try {
      const res = await fetch(`/backend/api/v1/connections/${c.id}/test`, {
        method: "POST",
        credentials: "same-origin",
        headers: csrfHeaders(),
      });
      if (res.ok) {
        const data: TestResult = await res.json();
        setTestResults((prev) => ({ ...prev, [c.id]: data }));
      }
      await load();
    } finally {
      setTestingId(null);
    }
  };

  const disable = async (c: ConnectionOut) => {
    if (!window.confirm(t("connDisableConfirm"))) return;
    const res = await fetch(`/backend/api/v1/connections/${c.id}`, {
      method: "DELETE",
      credentials: "same-origin",
      headers: csrfHeaders(),
    });
    if (res.ok) await load();
  };

  const dateFmt = new Intl.DateTimeFormat(locale === "ar" ? "ar" : "en", {
    dateStyle: "medium",
  });

  return (
    <div className="flex-1 flex flex-col">
      <Header titleKey="connections" />
      <main className="flex-1 p-6">
        <div className="mb-4 flex items-center justify-between">
          <div />
          {canWrite && (
            <button
              onClick={openCreate}
              className="rounded-md bg-emerald-500 px-4 py-2 text-sm font-medium text-slate-950 transition-colors hover:bg-emerald-400"
            >
              {t("connNew")}
            </button>
          )}
        </div>

        {loadError && (
          <p className="mb-4 rounded-md border border-red-800 bg-red-950/40 p-3 text-sm text-red-300">
            {t("connLoadError")}
          </p>
        )}

        {rows === null ? (
          <p className="text-slate-400">{t("loading")}</p>
        ) : rows.length === 0 && !loadError ? (
          <div className="rounded-lg border border-dashed border-slate-700 bg-slate-900/40 p-10 text-center">
            <p className="text-slate-300">{t("connEmpty")}</p>
            <p className="mt-2 text-sm text-slate-500">{t("connEmptyHint")}</p>
          </div>
        ) : rows.length > 0 ? (
          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-sm">
              <thead className="bg-slate-900 text-slate-400">
                <tr>
                  <th className="px-4 py-3 text-start font-medium">{t("connName")}</th>
                  <th className="px-4 py-3 text-start font-medium">{t("connProvider")}</th>
                  <th className="px-4 py-3 text-start font-medium">{t("connBaseUrl")}</th>
                  <th className="px-4 py-3 text-start font-medium">{t("connDatabase")}</th>
                  <th className="px-4 py-3 text-start font-medium">{t("connUsername")}</th>
                  <th className="px-4 py-3 text-start font-medium">{t("connStatus")}</th>
                  <th className="px-4 py-3 text-start font-medium">{t("connCredentials")}</th>
                  <th className="px-4 py-3 text-start font-medium">{t("connOdooVersion")}</th>
                  <th className="px-4 py-3 text-start font-medium">{t("connLastTest")}</th>
                  <th className="px-4 py-3 text-start font-medium">{t("connUpdated")}</th>
                  {canWrite && (
                    <th className="px-4 py-3 text-start font-medium">{t("connActions")}</th>
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 bg-slate-950/40">
                {rows.map((c) => (
                  <tr key={c.id} className="text-slate-200">
                    <td className="px-4 py-3 font-medium text-white">{c.name}</td>
                    <td className="px-4 py-3">{c.provider}</td>
                    <td className="px-4 py-3 text-slate-400" dir="ltr">
                      {c.base_url}
                    </td>
                    <td className="px-4 py-3">{c.database_name ?? "—"}</td>
                    <td className="px-4 py-3">{c.username ?? "—"}</td>
                    <td className="px-4 py-3">
                      <span
                        className={
                          c.status === "configured"
                            ? "rounded-full bg-emerald-950 px-2.5 py-1 text-xs text-emerald-400"
                            : "rounded-full bg-slate-800 px-2.5 py-1 text-xs text-slate-400"
                        }
                      >
                        {c.status === "configured" ? t("connConfigured") : t("connDisabled")}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {c.has_credentials ? t("connCredsSet") : t("connCredsMissing")}
                    </td>
                    <td className="px-4 py-3 text-slate-400" dir="ltr">
                      {c.detected_odoo_version
                        ? `${c.detected_odoo_version}${
                            c.detected_edition && c.detected_edition !== "unknown"
                              ? ` (${
                                  c.detected_edition === "enterprise"
                                    ? t("connEnterprise")
                                    : t("connCommunity")
                                })`
                              : ""
                          }${c.selected_transport ? ` · ${c.selected_transport}` : ""}`
                        : "—"}
                    </td>
                    <td className="px-4 py-3">
                      {c.last_test_status === "success" ? (
                        <span className="rounded-full bg-emerald-950 px-2.5 py-1 text-xs text-emerald-400">
                          {t("connTestOk")}
                        </span>
                      ) : c.last_test_status === "error" ? (
                        <span
                          className="rounded-full bg-red-950 px-2.5 py-1 text-xs text-red-400"
                          title={c.last_test_error_code ?? undefined}
                        >
                          {t("connTestFail")}
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                      {c.last_tested_at && (
                        <span className="ms-2 text-xs text-slate-500">
                          {dateFmt.format(new Date(c.last_tested_at))}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400">{dateFmt.format(new Date(c.updated_at))}</td>
                    {canWrite && (
                      <td className="px-4 py-3">
                        <div className="flex gap-3">
                          {c.status !== "disabled" && c.has_credentials && (
                            <button
                              onClick={() => void testConnection(c)}
                              disabled={testingId === c.id}
                              className="text-sky-400 hover:text-sky-300 disabled:opacity-60"
                            >
                              {testingId === c.id ? t("connTesting") : t("connTest")}
                            </button>
                          )}
                          <button
                            onClick={() => openEdit(c)}
                            className="text-emerald-400 hover:text-emerald-300"
                          >
                            {t("connEdit")}
                          </button>
                          {c.status !== "disabled" && (
                            <button
                              onClick={() => void disable(c)}
                              className="text-red-400 hover:text-red-300"
                            >
                              {t("connDisable")}
                            </button>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}

        {showForm && canWrite && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
            <form
              onSubmit={submit}
              className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-xl"
            >
              <h2 className="text-lg font-semibold text-white">
                {editing ? t("connEditTitle") : t("connCreateTitle")}
              </h2>

              <div className="mt-4 grid gap-4">
                <label className="text-sm text-slate-300">
                  {t("connName")}
                  <input
                    required
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-emerald-500"
                  />
                </label>
                <label className="text-sm text-slate-300">
                  {t("connProvider")}
                  <select
                    disabled
                    value="odoo"
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-white"
                  >
                    <option value="odoo">Odoo</option>
                  </select>
                </label>
                <label className="text-sm text-slate-300">
                  {t("connBaseUrl")}
                  <input
                    required
                    type="url"
                    dir="ltr"
                    placeholder="https://example.odoo.com"
                    value={form.base_url}
                    onChange={(e) => setForm({ ...form, base_url: e.target.value })}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-emerald-500"
                  />
                </label>
                <label className="text-sm text-slate-300">
                  {t("connDatabase")}
                  <input
                    dir="ltr"
                    value={form.database_name}
                    onChange={(e) => setForm({ ...form, database_name: e.target.value })}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-emerald-500"
                  />
                </label>
                <label className="text-sm text-slate-300">
                  {t("connUsername")}
                  <input
                    dir="ltr"
                    value={form.username}
                    onChange={(e) => setForm({ ...form, username: e.target.value })}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-emerald-500"
                  />
                </label>
                <label className="text-sm text-slate-300">
                  {t("connAuthMode")}
                  <select
                    value={form.auth_mode}
                    onChange={(e) => setForm({ ...form, auth_mode: e.target.value })}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-emerald-500"
                  >
                    <option value="auto">{t("connAuthAuto")}</option>
                    <option value="password">{t("connAuthPassword")}</option>
                    <option value="api_key">{t("connAuthApiKey")}</option>
                  </select>
                </label>
                <label className="text-sm text-slate-300">
                  {t("connPasswordLabel")}
                  <input
                    type="password"
                    autoComplete="new-password"
                    required={!editing}
                    value={form.secret}
                    onChange={(e) => setForm({ ...form, secret: e.target.value })}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none focus:border-emerald-500"
                  />
                  {editing && (
                    <span className="mt-1 block text-xs text-slate-500">
                      {t("connKeepSecretHint")}
                    </span>
                  )}
                </label>
              </div>

              {formError && <p className="mt-4 text-sm text-red-400">{formError}</p>}

              <div className="mt-6 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => {
                    // Clear secret/form state on cancel.
                    setForm(emptyForm);
                    setEditing(null);
                    setFormError(null);
                    setShowForm(false);
                  }}
                  className="rounded-md border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
                >
                  {t("connCancel")}
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="rounded-md bg-emerald-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-emerald-400 disabled:opacity-60"
                >
                  {saving ? t("connSaving") : t("connSave")}
                </button>
              </div>
            </form>
          </div>
        )}
      </main>
    </div>
  );
}
