"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState, type FormEvent } from "react";
import { safeNext } from "../../lib/links";
import { getPb } from "../../lib/pb";

export default function LoginPage() {
  const router = useRouter();
  // where the reader was going when the guard stopped them (U0)
  const next = safeNext(useSearchParams().get("next"));
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await getPb().collection("users").authWithPassword(email, password);
      router.replace(next);
    } catch {
      setError("sign-in failed — check email and password");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel login-card">
      <h1>Sign in</h1>
      <form onSubmit={submit}>
        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="text"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="username"
          autoFocus
        />
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
        />
        <div style={{ marginTop: 18 }}>
          <button className="btn primary" type="submit" disabled={busy}>
            {busy ? "signing in…" : "Sign in"}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </form>
      <p className="hint">
        Local prototype accounts (seeded by <code>rampscan serve</code>):<br />
        <code>viewer@rampscan.local</code> · <code>approver@rampscan.local</code>
        <br />
        password: <code>rampscan-demo</code>
      </p>
    </div>
  );
}
