import { useMemo, useState } from "react";
import { getMemdumps } from "./api.js";
import { Pagination, useLocalPagination } from "./Pagination.jsx";
import { SEVERITY_CLASS, useOptionalJson } from "./AnalysisVerdict.jsx";

const INDICATOR_CLASS = { 3: "bg-danger", 2: "bg-warning text-dark" };
const LEVEL_RANK = { high: 0, medium: 1, low: 2, clean: 3 };
const hasResult = (d) =>
    Boolean(
        d.yara?.length ||
            d.malware_configs?.length ||
            d.indicators?.length ||
            d.embedded_executables ||
            d.findings?.some(
                (f) => f.severity === "high" || f.severity === "medium",
            ),
    );
// Dumps with something to look at first: YARA hits, then insight indicators, then the analyzer's level.
const interest = (d) => [
    d.malware_configs?.length ? 0 : 1,
    d.yara?.length ? 0 : 1,
    d.indicators?.length ? 0 : 1,
    LEVEL_RANK[d.level] ?? 4,
    d.sample_tree ? 0 : 1,
];
const STOPPED_TEXT = {
    "time budget":
        "The scan stopped at its time budget (static.memdump_scan_budget_s); the rest were not scanned.",
    "dump limit":
        "The scan stopped at its dump limit (static.memdump_scan_max); the rest were not scanned.",
};

const LEVEL_CLASS = {
    high: "text-danger",
    medium: "text-warning-emphasis",
    low: "text-body",
    clean: "text-muted",
};

const size = (bytes) =>
    bytes >= 1 << 20
        ? `${(bytes / (1 << 20)).toFixed(1)} MiB`
        : `${Math.max(1, Math.round(bytes / 1024))} KiB`;

function DumpRow({ dump }) {
    const iocs = Object.values(dump.iocs || {}).flat();
    return (
        <tr>
            <td>
                <div className="fw-semibold text-break" title={dump.process}>
                    {dump.process?.split("\\").pop() || "–"}
                    {dump.sample_tree ? (
                        <span className="badge bg-primary ms-1">sample</span>
                    ) : null}
                </div>
                <div className="small text-muted">
                    PID {dump.pid ?? "–"} · {dump.reason || "–"}
                </div>
                <div className="small text-muted font-monospace text-break">
                    {dump.address || ""}
                </div>
                <div className="small text-muted">
                    {dump.format || "–"}
                    {dump.pe_kind ? ` · ${dump.pe_kind}` : ""} ·{" "}
                    {size(dump.size)}
                </div>
                <div
                    className="small font-monospace text-muted"
                    title={dump.sha256}
                >
                    {dump.sha256?.slice(0, 16)}
                </div>
            </td>
            <td className={LEVEL_CLASS[dump.level] || ""}>
                {dump.error ? (
                    <span className="text-warning-emphasis" title={dump.error}>
                        error
                    </span>
                ) : (
                    <>
                        <div className="fw-semibold">{dump.level || "–"}</div>
                        <div className="small">{dump.score ?? "–"}/100</div>
                    </>
                )}
            </td>
            <td>
                {dump.yara?.map((rule) => (
                    <span key={rule} className="badge bg-danger me-1">
                        {rule}
                    </span>
                ))}
                {dump.findings?.map((f) => (
                    <div key={f.id} className="small">
                        <span
                            className={`badge me-1 ${SEVERITY_CLASS[f.severity] || "bg-secondary"}`}
                        >
                            {f.severity}
                        </span>
                        {f.title}
                    </div>
                ))}
                {dump.indicators?.map((ind) => (
                    <div key={ind.title} className="small">
                        <span
                            className={`badge me-1 ${INDICATOR_CLASS[ind.severity] || "bg-secondary"}`}
                        >
                            {ind.severity >= 3 ? "high" : "medium"}
                        </span>
                        {ind.title}
                        {ind.attack?.length ? (
                            <span className="text-muted ms-1">
                                {ind.attack.join(", ")}
                            </span>
                        ) : null}
                    </div>
                ))}
                {dump.embedded_executables ? (
                    <div className="small">
                        {dump.embedded_executables} embedded executable(s)
                    </div>
                ) : null}
                {iocs.length ? (
                    <div className="small font-monospace text-break">
                        {iocs.join(", ")}
                    </div>
                ) : null}
            </td>
        </tr>
    );
}

function DumpTable({ scanned }) {
    const [onlyResults, setOnlyResults] = useState(
        () => scanned.length > 25 && scanned.some(hasResult),
    );
    const rows = useMemo(() => {
        const list = onlyResults ? scanned.filter(hasResult) : [...scanned];
        return list.sort((a, b) => {
            const x = interest(a);
            const y = interest(b);
            for (let i = 0; i < x.length; i++)
                if (x[i] !== y[i]) return x[i] - y[i];
            return 0;
        });
    }, [scanned, onlyResults]);
    const pager = useLocalPagination(rows.length, 25);
    return (
        <>
            <div className="chimera-table-toolbar">
                <label className="form-check form-switch m-0 small">
                    <input
                        className="form-check-input"
                        type="checkbox"
                        role="switch"
                        checked={onlyResults}
                        onChange={(e) => {
                            setOnlyResults(e.target.checked);
                            pager.setPage(1);
                        }}
                    />
                    <span className="form-check-label">
                        Only dumps with results (
                        {scanned.filter(hasResult).length} of {scanned.length})
                    </span>
                </label>
            </div>
            <div className="chimera-table-scroll">
                <table
                    aria-label="Scanned memory dumps"
                    className="table table-sm align-top memdump-table chimera-data-table"
                >
                    <colgroup>
                        <col style={{ width: "14rem" }} />
                        <col style={{ width: "6rem" }} />
                        <col />
                    </colgroup>
                    <thead>
                        <tr>
                            <th>Dump</th>
                            <th>Assessment</th>
                            <th>YARA · indicators · findings · IOCs</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pager.slice(rows).map((dump) => (
                            <DumpRow key={dump.member} dump={dump} />
                        ))}
                    </tbody>
                </table>
            </div>
            <Pagination pager={pager} label="Memory dump pages" noun="dumps" />
        </>
    );
}

// Config values as short text: nested objects flattened one level, long lists cut.
const fieldText = (value) =>
    Array.isArray(value)
        ? value.map(fieldText).join(", ")
        : value && typeof value === "object"
          ? Object.entries(value)
                .map(([k, v]) => `${k}: ${fieldText(v)}`)
                .join("; ")
          : String(value);

export function MalwareConfigs({ configs }) {
    if (!configs?.length) return null;
    return (
        <section className="mb-3" aria-label="Malware configurations">
            <h6 className="mb-1">Malware configuration</h6>
            <p className="small text-muted mb-2">
                Decoded from memory with CERT Polska&apos;s malduck modules
                (njRAT, Remcos, REvil, Cobalt Strike, GraphicalProton). A
                decoded configuration identifies the family: its C2 addresses
                are the sample&apos;s real infrastructure, which the contained
                network never let it reach.
            </p>
            {configs.map((c, i) => (
                <div className="card mb-2 border-danger-subtle" key={i}>
                    <div className="card-body p-3">
                        <div className="d-flex flex-wrap gap-2 align-items-baseline">
                            <span className="badge bg-danger">{c.family}</span>
                            {c.dumps?.length ? (
                                <span className="small text-muted">
                                    found in{" "}
                                    {[
                                        ...new Set(
                                            c.dumps.map(
                                                (d) =>
                                                    `${d.process || "?"}${d.pid != null ? ` (PID ${d.pid})` : ""}`,
                                            ),
                                        ),
                                    ].join(", ")}
                                </span>
                            ) : null}
                        </div>
                        {c.c2?.length ? (
                            <div className="mt-2">
                                <div className="small text-muted">C2</div>
                                <ul className="list-unstyled mb-0">
                                    {c.c2.map((e) => (
                                        <li key={e}>
                                            <code>{e}</code>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        ) : null}
                        {Object.keys(c.fields || {}).length ? (
                            <details className="mt-2">
                                <summary className="small">
                                    All fields ({Object.keys(c.fields).length})
                                </summary>
                                <table className="table table-sm chimera-data-table mb-0 mt-1">
                                    <tbody>
                                        {Object.entries(c.fields).map(
                                            ([k, v]) => (
                                                <tr key={k}>
                                                    <th
                                                        scope="row"
                                                        className="cell-short"
                                                    >
                                                        {k}
                                                    </th>
                                                    <td className="cell-long">
                                                        <code>
                                                            {fieldText(v)}
                                                        </code>
                                                    </td>
                                                </tr>
                                            ),
                                        )}
                                    </tbody>
                                </table>
                            </details>
                        ) : null}
                    </div>
                </div>
            ))}
        </section>
    );
}

export function HttpFingerprints({ network }) {
    if (!network) return null;
    if (network.error)
        return (
            <p className="small text-muted">
                HTTP fingerprints: {network.error}
            </p>
        );
    const prints = network.fingerprints || [];
    return (
        <section className="mb-3" aria-label="HTTP request fingerprints">
            <h6 className="mb-1">HTTP request fingerprints</h6>
            <p className="small text-muted mb-2">
                CERT Polska&apos;s hfinger over the run&apos;s traffic: how each
                client builds its requests (method, version, header order and
                values, URL and payload features). Requests from one malware
                family share a fingerprint whatever server they go to, so a
                fingerprint can be searched for in other runs or in proxy logs.
            </p>
            {prints.length ? (
                <div className="chimera-table-scroll">
                    <table className="table table-sm chimera-data-table mb-0">
                        <thead>
                            <tr>
                                <th scope="col">Fingerprint</th>
                                <th scope="col">Requests</th>
                            </tr>
                        </thead>
                        <tbody>
                            {prints.map((p) => (
                                <tr key={p.fingerprint}>
                                    <td className="cell-long">
                                        <code className="text-break">
                                            {p.fingerprint}
                                        </code>
                                    </td>
                                    <td className="cell-short">{p.count}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {network.truncated ? (
                        <p className="small text-muted mb-0">
                            Only the first requests were fingerprinted.
                        </p>
                    ) : null}
                </div>
            ) : (
                <p className="small text-muted">
                    No HTTP requests in the traffic.
                </p>
            )}
        </section>
    );
}

export default function MemoryDumps({ analysisId }) {
    const state = useOptionalJson(getMemdumps, analysisId);
    if (state.loading) return <div role="status">Loading memory dumps…</div>;
    if (state.missing)
        return (
            <div role="status">
                {state.polling
                    ? "Memory dumps not scanned yet: the scan runs on the deep queue after the analysis (this updates by itself)."
                    : "No memory-dump scan for this analysis (off on this server, or the run took no dumps)."}
            </div>
        );
    if (state.error)
        return <div role="status">Error: {String(state.error)}</div>;
    const doc = state.data;
    const hits = doc.scanned.filter((d) => d.yara?.length).length;
    return (
        <div>
            <p className="small text-muted">
                DRAKVUF dumps memory regions on heuristics (remote threads,
                written-then-executed memory, freed images). Every distinct dump
                goes through the static analyzer: YARA, PE parsing, embedded
                executables, strings and IOCs. These results are not classifier
                features.
            </p>
            {doc.error ? (
                <div className="alert alert-warning">{doc.error}</div>
            ) : null}
            <div className="static-metrics mb-3">
                {[
                    ["Dumps in the run", doc.dumps_total],
                    ["Scanned", doc.scanned.length],
                    ["With YARA matches", hits],
                    ["Duplicates", doc.duplicates],
                    ["Not scanned", doc.skipped],
                    ...(doc.too_large_or_empty != null
                        ? [["Too large or empty", doc.too_large_or_empty]]
                        : []),
                    ["Scan time", doc.wall_s != null ? `${doc.wall_s} s` : "–"],
                ].map(([label, value]) => (
                    <div className="card" key={label}>
                        <div className="card-body p-3">
                            <div className="small text-muted">{label}</div>
                            <div
                                className={`fw-semibold ${label === "With YARA matches" && value ? "text-danger" : ""}`}
                            >
                                {value}
                            </div>
                        </div>
                    </div>
                ))}
            </div>
            {doc.stopped ? (
                <div className="alert alert-secondary small py-2">
                    {STOPPED_TEXT[doc.stopped] || `Stopped: ${doc.stopped}.`}
                </div>
            ) : null}
            <MalwareConfigs configs={doc.malware_configs} />
            <HttpFingerprints network={doc.network_fingerprints} />
            {doc.scanned.length ? (
                <DumpTable scanned={doc.scanned} />
            ) : (
                <div className="text-muted">No dump was scanned.</div>
            )}
        </div>
    );
}
