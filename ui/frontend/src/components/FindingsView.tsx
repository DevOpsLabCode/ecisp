import { Fragment, useMemo, useState } from "react";
import SeverityBadge from "./SeverityBadge";
import type { Finding, ScanResults } from "../types";

interface FlatFinding {
  key: string;
  service: string;
  id: string;
  finding: Finding;
  flaggedCount: number;
}

function flaggedCountOf(finding: Finding): number {
  return finding.flagged_items ?? finding.items?.length ?? 0;
}

function flatten(results: ScanResults): FlatFinding[] {
  const out: FlatFinding[] = [];
  const services = results.services ?? {};
  for (const [serviceCode, serviceData] of Object.entries(services)) {
    const findings = serviceData?.findings ?? {};
    for (const [findingId, finding] of Object.entries(findings)) {
      out.push({
        key: `${serviceCode}.${findingId}`,
        service: serviceCode,
        id: findingId,
        finding,
        flaggedCount: flaggedCountOf(finding),
      });
    }
  }
  return out;
}

const LEVELS = ["danger", "warning", "good"] as const;

/** Any level outside the three known buckets is treated as a warning, both
 * for the stat tiles and for the filter toggles -- keeping them consistent
 * so a finding counted in a tile always appears when that filter is active. */
function normalizeLevel(level: string): (typeof LEVELS)[number] {
  return (LEVELS as readonly string[]).includes(level) ? (level as (typeof LEVELS)[number]) : "warning";
}

export default function FindingsView({ results }: { results: ScanResults }) {
  const all = useMemo(() => flatten(results), [results]);
  const [levelFilter, setLevelFilter] = useState<Set<string>>(new Set(["danger", "warning"]));
  const [serviceFilter, setServiceFilter] = useState<string>("");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const serviceOptions = useMemo(
    () => Array.from(new Set(all.map((f) => f.service))).sort(),
    [all]
  );

  const counts = useMemo(() => {
    const c: Record<string, number> = { danger: 0, warning: 0, good: 0 };
    for (const f of all) {
      if (f.flaggedCount > 0) {
        c[normalizeLevel(f.finding.level)] += 1;
      }
    }
    return c;
  }, [all]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return all
      .filter((f) => {
        if (f.flaggedCount === 0) return false;
        if (!levelFilter.has(normalizeLevel(f.finding.level))) return false;
        if (serviceFilter && f.service !== serviceFilter) return false;
        if (q && !`${f.id} ${f.finding.description || ""}`.toLowerCase().includes(q)) return false;
        return true;
      })
      .sort((a, b) => {
        const order: Record<string, number> = { danger: 0, warning: 1, good: 2 };
        const ao = order[normalizeLevel(a.finding.level)];
        const bo = order[normalizeLevel(b.finding.level)];
        if (ao !== bo) return ao - bo;
        return b.flaggedCount - a.flaggedCount;
      });
  }, [all, levelFilter, serviceFilter, search]);

  const toggleLevel = (lvl: string) => {
    setLevelFilter((prev) => {
      const next = new Set(prev);
      if (next.has(lvl)) next.delete(lvl);
      else next.add(lvl);
      return next;
    });
  };

  return (
    <div>
      <div className="stat-row">
        <div className="stat-tile danger">
          <div className="num">{counts.danger}</div>
          <div className="label">Danger findings</div>
        </div>
        <div className="stat-tile warning">
          <div className="num">{counts.warning}</div>
          <div className="label">Warning findings</div>
        </div>
        <div className="stat-tile success">
          <div className="num">{counts.good}</div>
          <div className="label">Good-practice findings</div>
        </div>
        <div className="stat-tile">
          <div className="num">{results.service_list?.length ?? serviceOptions.length}</div>
          <div className="label">Services scanned</div>
        </div>
      </div>

      <div className="toolbar">
        {LEVELS.map((lvl) => (
          <button
            key={lvl}
            type="button"
            className={`method-tab${levelFilter.has(lvl) ? " active" : ""}`}
            onClick={() => toggleLevel(lvl)}
          >
            {lvl}
          </button>
        ))}
        <select value={serviceFilter} onChange={(e) => setServiceFilter(e.target.value)}>
          <option value="">All services</option>
          {serviceOptions.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <input
          type="text"
          placeholder="Search findings…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1, minWidth: 200 }}
        />
      </div>

      {filtered.length === 0 ? (
        <div className="card">
          <div className="empty-state">No findings match the current filters.</div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th style={{ width: 90 }}>Severity</th>
                <th style={{ width: 120 }}>Service</th>
                <th>Finding</th>
                <th style={{ width: 90 }}>Flagged</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <Fragment key={f.key}>
                  <tr className="clickable" onClick={() => setExpanded(expanded === f.key ? null : f.key)}>
                    <td>
                      <SeverityBadge level={f.finding.level} />
                    </td>
                    <td>{f.service}</td>
                    <td>{f.finding.description || f.id}</td>
                    <td>{f.flaggedCount}</td>
                  </tr>
                  {expanded === f.key && (
                    <tr>
                      <td colSpan={4} style={{ borderBottom: "1px solid var(--border)" }}>
                        <dl className="finding-detail">
                          {f.finding.rationale && (
                            <>
                              <dt>Rationale</dt>
                              <dd>{f.finding.rationale}</dd>
                            </>
                          )}
                          {f.finding.remediation && (
                            <>
                              <dt>Remediation</dt>
                              <dd>{f.finding.remediation}</dd>
                            </>
                          )}
                          {f.finding.items && f.finding.items.length > 0 && (
                            <>
                              <dt>Affected resources ({f.finding.items.length})</dt>
                              <dd>
                                <ul>
                                  {f.finding.items.slice(0, 50).map((item) => (
                                    <li key={item}>{item}</li>
                                  ))}
                                </ul>
                                {f.finding.items.length > 50 && (
                                  <div className="help">…and {f.finding.items.length - 50} more</div>
                                )}
                              </dd>
                            </>
                          )}
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
