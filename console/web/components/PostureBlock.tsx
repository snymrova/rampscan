"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { themeHref } from "../lib/links";
import { clockState, formatDuration, MVX_WINDOW_DAYS } from "../lib/mvx";
import { useCollection } from "../lib/pb";
import { type Posture, postureSentence, STANDING_ORDER, STANDING_WORD, type Standing } from "../lib/posture";
import { deriveActionQueue } from "../lib/queue";
import { useRepoScope } from "../lib/scope";
import type { DaemonEventRecord, DriftRecord, RegisterRecord, ScanRunRecord } from "../lib/types";
import { EntityLink } from "./EntityLink";

// L0, the surface (Plan U, U2's posture block): one numeral, one computed
// sentence, the themes as strata worst first, and on the right the next
// three things to do and the tightest clock. Every count is the posture
// fold's; the queue and the clock are the Queue's and the Clock's own
// derivations, read through the same repo scope.

export function PostureBlock({
  posture,
  repo,
  certClass,
  focusTheme,
}: {
  posture: Posture;
  repo: string | null;
  certClass: "b" | "c";
  focusTheme: string | null;
}) {
  const { scoped } = useRepoScope();
  return (
    <section className="posture" data-level="posture" aria-label="posture">
      <div className="posture-main">
        <p className={`posture-numeral ${posture.total > 0 && posture.floorMet === posture.total ? "all-met" : ""}`}>
          <span className="met">{posture.floorMet}</span>
          <span className="of">/</span>
          <span className="total">{posture.total}</span>
          <span className="word">
            indicators
            <br />
            meet the floor
          </span>
        </p>
        <p className="posture-sentence">{postureSentence(posture)}</p>

        <div className="strata-head">
          <span className="strata-title">Theme strata</span>
          <span className="legend">
            {STANDING_ORDER.map((s) => (
              <span key={s}>
                <i className={`cell s-${s}`} aria-hidden="true" />
                {STANDING_WORD[s]} {posture.counts[s]}
              </span>
            ))}
          </span>
        </div>
        <ol className="strata">
          {posture.strata.map((stratum) => (
            <li key={stratum.key} className={`stratum ${focusTheme === stratum.key ? "focus" : ""}`}>
              <Link href={scoped(themeHref(stratum.key))} className="stratum-code">
                {stratum.key}
              </Link>
              <span className="stratum-name">{stratum.name}</span>
              <span className="stratum-bar">
                {STANDING_ORDER.filter((s) => stratum.counts[s] > 0).map((s) => (
                  <Run key={s} standing={s} ksis={stratum.ksis.filter((k) => k.standing === s).map((k) => k.ksi)} repo={repo} />
                ))}
              </span>
            </li>
          ))}
        </ol>
      </div>
      <aside className="posture-side">
        <NextActions repo={repo} certClass={certClass} />
        <TightestClock repo={repo} certClass={certClass} />
      </aside>
    </section>
  );
}

/** one standing's run of lamps in a stratum, then its count and its word: the fill is never alone */
function Run({ standing, ksis, repo }: { standing: Standing; ksis: string[]; repo: string | null }) {
  return (
    <span className="cellrun" title={`${ksis.length} ${STANDING_WORD[standing]}`}>
      {ksis.map((k) => (
        <EntityLink key={k} kind="ksi" id={k} repo={repo ?? undefined} className={`cell s-${standing}`} title={`${k} · ${STANDING_WORD[standing]}`}>
          <span className="sr-only">
            {k} {STANDING_WORD[standing]}
          </span>
        </EntityLink>
      ))}
      <span className="run-count">
        {ksis.length} {STANDING_WORD[standing]}
      </span>
    </span>
  );
}

function useNow(ms: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}

function NextActions({ repo, certClass }: { repo: string | null; certClass: "b" | "c" }) {
  const registers = useCollection<RegisterRecord>("registers");
  const drift = useCollection<DriftRecord>("drift");
  const events = useCollection<DaemonEventRecord>("daemon_events");
  const runs = useCollection<ScanRunRecord>("scan_runs");
  const now = useNow(30_000);
  const { scoped } = useRepoScope();
  const items = useMemo(
    () =>
      deriveActionQueue({
        registers: registers.records,
        drift: drift.records,
        events: events.records,
        runs: runs.records,
        certClass,
        now,
      }).filter((i) => repo === null || i.repo === repo),
    [registers.records, drift.records, events.records, runs.records, certClass, now, repo],
  );
  const loading = registers.loading || drift.loading || events.loading || runs.loading;
  const top = items.slice(0, 3);
  return (
    <div className="side-block">
      <h2 className="side-title">Next three actions</h2>
      {loading && items.length === 0 ? (
        <p className="faint">reading the queue…</p>
      ) : top.length === 0 ? (
        <p className="muted">Nothing is queued: no divergence, nothing expiring, no new violation, no fixable skip.</p>
      ) : (
        <ol className="actions">
          {top.map((item) => (
            <li key={`${item.kind}-${item.repo}-${item.recipeIds.join(",")}-${item.at}`} className="action">
              <span className="action-head">
                <span className={`pill qkind-${item.kind}`}>{item.kind.replace(/-/g, " ")}</span>
                {item.recipeIds.slice(0, 2).map((r) => (
                  <EntityLink key={r} kind="check" recipe={r} repo={item.repo} />
                ))}
              </span>
              <span className="action-fix">{item.plain ?? item.title}</span>
            </li>
          ))}
        </ol>
      )}
      {items.length > 3 && (
        <p className="faint" style={{ margin: "12px 0 0", fontSize: 12.5 }}>
          <Link href={scoped("/queue")}>{items.length - 3} more in the queue</Link>
        </p>
      )}
    </div>
  );
}

function TightestClock({ repo, certClass }: { repo: string | null; certClass: "b" | "c" }) {
  const registers = useCollection<RegisterRecord>("registers");
  const now = useNow(30_000);
  const { scoped } = useRepoScope();
  const tightest = useMemo(() => {
    const live = registers.records.filter(
      (r) => (repo === null || r.repo === repo) && r.fresh_as_of && (r.state === "evidenced" || r.state === "violated"),
    );
    let best: { recipe: string; ms: number; status: string } | null = null;
    for (const r of live) {
      const c = clockState(r.fresh_as_of, certClass, now);
      if (best === null || c.remainingMs < best.ms) best = { recipe: r.recipe_id, ms: c.remainingMs, status: c.status };
    }
    return { best, count: live.length };
  }, [registers.records, repo, certClass, now]);
  const { best, count } = tightest;
  return (
    <div className="side-block">
      <h2 className="side-title">MVX clock</h2>
      {best === null ? (
        <p className="muted">No live evidence in this scope, so no clock is running.</p>
      ) : (
        <div className="gauge">
          <span className={`gauge-value ${best.status}`}>
            {best.ms <= 0 ? `expired ${formatDuration(best.ms)} ago` : formatDuration(best.ms)}
            <small>of {MVX_WINDOW_DAYS[certClass]}d</small>
          </span>
          <span className="gauge-note">
            the tightest of {count} live {count === 1 ? "clock" : "clocks"}, on{" "}
            <EntityLink kind="check" recipe={best.recipe} repo={repo ?? ""} /> ·{" "}
            <Link href={scoped("/clock")}>every clock</Link>
          </span>
        </div>
      )}
    </div>
  );
}
