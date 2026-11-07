import { useEffect, useState } from "react";
import { getMobileDynamic } from "../api.js";

// Android dynamic analysis (GET /api/mobile/<id>, chimera-mobile-dynamic/1). Polls while queued or running.
const POLL_MS = 10000;
const STEP_LABELS = {
    mobsf_start: "MobSF started",
    device_boot: "Android guest booted",
    static_scan: "MobSF static scan (in the mobile VM)",
    start_analysis: "App installed, proxy and CA set up",
    frida_instrument: "Frida hooks attached",
    frida_server: "frida-server running on the guest",
    app_running: "App process running",
    exported_activities: "Exported activities started",
    monkey: "Simulated taps (monkey)",
    api_monitor: "API monitor read",
    stop_analysis: "Logs and app data collected",
    report: "Dynamic report generated",
};

function useMobileDynamic(analysisId) {
    const [state, setState] = useState({ loading: true });
    useEffect(() => {
        let active = true;
        let timer;
        const load = () => {
            getMobileDynamic({ analysisId })
                .then((data) => {
                    if (!active) return;
                    setState({ data });
                    if (data?.status === "queued" || data?.status === "running")
                        timer = setTimeout(load, POLL_MS);
                })
                .catch((error) => {
                    if (!active) return;
                    setState(
                        error?.response?.status === 404
                            ? { missing: true }
                            : { error },
                    );
                });
        };
        load();
        return () => {
            active = false;
            clearTimeout(timer);
        };
    }, [analysisId]);
    return state;
}

function List({ label, items }) {
    if (!items?.length)
        return <p className="small text-muted mb-0">None observed.</p>;
    return (
        <ul aria-label={label} className="small mb-0 cell-long">
            {items.map((item) => (
                <li key={item}>
                    <code>{item}</code>
                </li>
            ))}
        </ul>
    );
}

export function MobileDynamicView({ analysisId }) {
    const state = useMobileDynamic(analysisId);
    if (state.loading) return <p className="text-muted">Loading…</p>;
    if (state.missing)
        return (
            <p className="text-muted">
                This app was analysed statically only (no run in the Android
                guest).
            </p>
        );
    if (state.error)
        return (
            <p className="text-danger">
                Could not load the dynamic analysis: {String(state.error)}
            </p>
        );
    const data = state.data;
    if (data.status === "queued" || data.status === "running")
        return (
            <div className="alert alert-info" role="status">
                The app is {data.status === "queued" ? "queued for" : "in"} its
                run in the Android guest ({data.run_s} s of app time, plus boot,
                install and report). This page updates by itself.
            </div>
        );
    const device = data.device || {};
    return (
        <div className="mobile-dynamic">
            <div
                className={`alert ${data.status === "finished" ? "alert-success" : "alert-warning"}`}
                role="status"
            >
                {data.status === "finished"
                    ? `Ran ${data.package || "the app"} for ${data.run_s} s in Android ${device["ro.build.version.release"] || "?"} (API ${device["ro.build.version.sdk"] || "?"}, ${device["ro.product.cpu.abi"] || "?"}).`
                    : `The run did not complete${data.error ? `: ${data.error}` : "."}`}{" "}
                Traffic went to the simulated Internet only;{" "}
                <a href={`/api/pcap_file/${analysisId}`}>download the PCAP</a>.
            </div>
            <section className="mb-4">
                <h3 className="h6">Run steps</h3>
                <ul className="list-unstyled small mb-0">
                    {(data.steps || []).map((s, i) => (
                        <li key={`${s.name}-${i}`}>
                            <span
                                className={
                                    s.ok ? "text-success" : "text-danger"
                                }
                                aria-label={s.ok ? "done" : "failed"}
                            >
                                {s.ok ? "✓" : "✗"}
                            </span>{" "}
                            {STEP_LABELS[s.name] || s.name}
                            {!s.ok && s.detail ? (
                                <span className="text-muted">
                                    {" "}
                                    — {s.detail}
                                </span>
                            ) : null}
                        </li>
                    ))}
                </ul>
            </section>
            {data.screenshots?.length ? (
                <section className="mb-4">
                    <h3 className="h6">Screenshots</h3>
                    <div className="d-flex flex-wrap gap-2">
                        {data.screenshots.map((s) => (
                            <figure key={s.file} className="mb-0">
                                <a
                                    href={`/api/mobile/${analysisId}/screen/${s.file}`}
                                >
                                    <img
                                        src={`/api/mobile/${analysisId}/screen/${s.file}`}
                                        alt={`Android screen: ${s.label}`}
                                        style={{ width: 240 }}
                                        className="border rounded"
                                    />
                                </a>
                                <figcaption className="small text-muted">
                                    {s.label}
                                </figcaption>
                            </figure>
                        ))}
                    </div>
                </section>
            ) : null}
            <section className="mb-4">
                <h3 className="h6">
                    Domains{" "}
                    <span className="badge bg-secondary">
                        {data.domains?.length || 0}
                    </span>
                </h3>
                <List label="Domains contacted" items={data.domains} />
            </section>
            <section className="mb-4">
                <h3 className="h6">
                    URLs{" "}
                    <span className="badge bg-secondary">
                        {data.urls?.length || 0}
                    </span>
                </h3>
                <List label="URLs requested" items={data.urls} />
            </section>
            <section className="mb-4">
                <h3 className="h6">
                    API calls (Frida){" "}
                    <span className="badge bg-secondary">
                        {data.api_calls?.length || 0}
                    </span>
                </h3>
                {data.api_calls?.length ? (
                    <div className="chimera-table-scroll">
                        <table
                            aria-label="API calls"
                            className="table table-sm chimera-data-table"
                        >
                            <thead>
                                <tr>
                                    <th>API</th>
                                    <th>Class</th>
                                    <th>Method</th>
                                    <th>Arguments</th>
                                    <th>Result</th>
                                </tr>
                            </thead>
                            <tbody>
                                {data.api_calls.map((c, i) => (
                                    <tr key={i}>
                                        <td>{c.api}</td>
                                        <td className="cell-long">{c.class}</td>
                                        <td>{c.method}</td>
                                        <td className="cell-long">
                                            <code>{c.arguments}</code>
                                        </td>
                                        <td className="cell-long">
                                            <code>{c.result}</code>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <p className="small text-muted mb-0">None recorded.</p>
                )}
            </section>
            {["sqlite", "xml_files", "other_files"].some(
                (k) => data[k]?.length,
            ) ? (
                <section className="mb-4">
                    <h3 className="h6">Files the app wrote</h3>
                    <List
                        label="Files the app wrote"
                        items={[
                            ...(data.sqlite || []),
                            ...(data.xml_files || []),
                            ...(data.other_files || []),
                        ]}
                    />
                </section>
            ) : null}
            {data.logcat_tail ? (
                <details className="mb-4">
                    <summary className="h6">logcat</summary>
                    <pre className="small border rounded p-2 chimera-log">
                        {data.logcat_tail}
                    </pre>
                </details>
            ) : null}
        </div>
    );
}
