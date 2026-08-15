"""
report/generate_report.py
=========================
HTML report generator with embedded matplotlib charts.

Produces a single self-contained HTML file with:
  1. Executive summary cards
  2. Five embedded charts (base64 PNG):
       a) Risk level donut
       b) Cracked vs. uncracked per protocol (grouped bar)
       c) Time-to-crack distribution (histogram)
       d) Attempts-before-crack CDF
       e) Hardened vs. normal success rate (comparison bar)
  3. Per-device cards with risk badge, credential details, attempt log
  4. Protocol vulnerability table
  5. Password pattern breakdown
  6. Hardening comparison section
  7. Methodology and recommendations appendix

All charts are embedded as base64-encoded PNG blobs so the report is fully
portable (single HTML file, no external dependencies to open it).
"""

import base64
import io
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

# matplotlib import — gracefully degrade if not installed
try:
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.gridspec import GridSpec
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


# ─────────────────────────────────────────────────────────────────────────────
# Color Palette & Helpers
# ─────────────────────────────────────────────────────────────────────────────

RISK_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "UNKNOWN":  "#6b7280",
}

PROTOCOL_COLORS = {
    "HTTP-like":    "#6366f1",
    "Telnet-like":  "#ec4899",
    "JSON-TCP":     "#14b8a6",
    "REST-like":    "#f59e0b",
}

BG = "#0f172a"       # dark navy background
CARD_BG = "#1e293b"  # card background
TEXT = "#e2e8f0"     # primary text
MUTED = "#94a3b8"    # secondary text

plt_style = {
    "figure.facecolor": BG,
    "axes.facecolor": CARD_BG,
    "axes.edgecolor": "#334155",
    "axes.labelcolor": TEXT,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "text.color": TEXT,
    "grid.color": "#334155",
    "grid.alpha": 0.5,
}


def _fig_to_b64(fig) -> str:
    """Render a matplotlib figure to a base64-encoded PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return encoded


# ─────────────────────────────────────────────────────────────────────────────
# Chart Generators
# ─────────────────────────────────────────────────────────────────────────────

def _chart_risk_donut(by_risk: Dict[str, int]) -> Optional[str]:
    """Donut chart: CRITICAL / HIGH / MEDIUM / LOW device counts."""
    with plt.rc_context(plt_style):
        fig, ax = plt.subplots(figsize=(4.5, 4.5))
        labels, sizes, colors = [], [], []
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = by_risk.get(level, 0)
            if count > 0:
                labels.append(f"{level}\n({count})")
                sizes.append(count)
                colors.append(RISK_COLORS[level])

        if not sizes:
            sizes, labels, colors = [1], ["No data"], [MUTED]

        wedges, _ = ax.pie(
            sizes, labels=None, colors=colors,
            startangle=90, wedgeprops={"width": 0.55, "edgecolor": BG, "linewidth": 2},
        )
        ax.legend(
            wedges, labels,
            loc="lower center", bbox_to_anchor=(0.5, -0.12),
            ncol=2, fontsize=9, framealpha=0,
        )
        ax.set_title("Risk Level Distribution", color=TEXT, fontsize=13, pad=12)
        fig.patch.set_facecolor(BG)
        return _fig_to_b64(fig)


def _chart_protocol_bars(protocol_analysis: Dict) -> Optional[str]:
    """Grouped bar chart: cracked vs. total per protocol."""
    with plt.rc_context(plt_style):
        protocols = list(protocol_analysis.keys())
        totals = [protocol_analysis[p]["total"] for p in protocols]
        cracked = [protocol_analysis[p]["cracked"] for p in protocols]

        x = range(len(protocols))
        w = 0.35

        fig, ax = plt.subplots(figsize=(6, 4))
        bars_total = ax.bar(
            [i - w / 2 for i in x], totals, w,
            label="Total", color="#334155", edgecolor=BG,
        )
        bars_cracked = ax.bar(
            [i + w / 2 for i in x], cracked, w,
            label="Cracked",
            color=[PROTOCOL_COLORS.get(p, "#6b7280") for p in protocols],
            edgecolor=BG,
        )

        # Value labels on bars
        for bar in bars_total + bars_cracked:
            h = bar.get_height()
            if h > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, h + 0.05,
                        str(int(h)), ha="center", va="bottom", fontsize=9)

        ax.set_xticks(list(x))
        ax.set_xticklabels(protocols, fontsize=9)
        ax.set_ylabel("# Devices")
        ax.set_title("Cracked vs. Total by Protocol", color=TEXT, fontsize=13)
        ax.legend(framealpha=0, fontsize=9)
        ax.set_ylim(0, max(totals, default=1) + 1)
        ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
        ax.grid(axis="y")
        fig.tight_layout()
        return _fig_to_b64(fig)


def _chart_time_to_crack(devices: List[Dict]) -> Optional[str]:
    """Histogram: time-to-crack distribution across cracked devices."""
    times = [d["time_to_crack_seconds"] for d in devices
             if d.get("cracked") and d.get("time_to_crack_seconds") is not None]
    if not times:
        return None

    with plt.rc_context(plt_style):
        fig, ax = plt.subplots(figsize=(6, 3.5))
        n_bins = min(len(times), 10)
        ax.hist(times, bins=n_bins, color="#6366f1", edgecolor=BG, linewidth=1.2)
        ax.axvline(sum(times) / len(times), color="#f97316", linestyle="--",
                   linewidth=1.5, label=f"Mean: {sum(times)/len(times):.2f}s")
        ax.set_xlabel("Seconds to Crack")
        ax.set_ylabel("# Devices")
        ax.set_title("Time-to-Crack Distribution", color=TEXT, fontsize=13)
        ax.legend(framealpha=0, fontsize=9)
        ax.grid(axis="y")
        fig.tight_layout()
        return _fig_to_b64(fig)


def _chart_attempts_cdf(devices: List[Dict]) -> Optional[str]:
    """CDF: cumulative % of cracked devices vs. number of attempts used."""
    attempt_counts = sorted(
        d["attempts"] for d in devices
        if d.get("cracked") and d.get("attempts")
    )
    if not attempt_counts:
        return None

    with plt.rc_context(plt_style):
        fig, ax = plt.subplots(figsize=(6, 3.5))
        n = len(attempt_counts)
        cdf_y = [(i + 1) / n * 100 for i in range(n)]
        ax.step(attempt_counts, cdf_y, color="#14b8a6", linewidth=2, where="post")
        ax.fill_between(attempt_counts, cdf_y, alpha=0.15, color="#14b8a6", step="post")
        ax.axhline(50, color="#94a3b8", linestyle=":", linewidth=1)
        ax.axhline(90, color="#94a3b8", linestyle=":", linewidth=1)
        ax.text(max(attempt_counts) * 0.02, 52, "50%", color=MUTED, fontsize=8)
        ax.text(max(attempt_counts) * 0.02, 92, "90%", color=MUTED, fontsize=8)
        ax.set_xlabel("Number of Attempts")
        ax.set_ylabel("Cumulative % of Devices Cracked")
        ax.set_title("Attempts-to-Crack CDF", color=TEXT, fontsize=13)
        ax.set_ylim(0, 105)
        ax.grid(axis="both")
        fig.tight_layout()
        return _fig_to_b64(fig)


def _chart_hardening_comparison(hardening: Dict) -> Optional[str]:
    """Side-by-side bar: crack rate before vs. after hardening."""
    if not hardening:
        return None

    with plt.rc_context(plt_style):
        fig, ax = plt.subplots(figsize=(5, 3.5))
        labels = ["Normal\n(No Hardening)", "Hardened\n(Lockout Active)"]
        rates = [
            hardening["normal"]["crack_rate_pct"],
            hardening["hardened"]["crack_rate_pct"],
        ]
        bar_colors = [RISK_COLORS["HIGH"], RISK_COLORS["LOW"]]
        bars = ax.bar(labels, rates, color=bar_colors, edgecolor=BG,
                      width=0.5, linewidth=1.5)
        for bar, rate in zip(bars, rates):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                    f"{rate:.0f}%", ha="center", fontsize=11, fontweight="bold")
        ax.set_ylabel("Crack Rate (%)")
        ax.set_title("Hardening Effectiveness\n(Before vs. After)", color=TEXT, fontsize=13)
        ax.set_ylim(0, 115)
        ax.grid(axis="y")
        fig.tight_layout()
        return _fig_to_b64(fig)


def _chart_password_patterns(patterns: Dict) -> Optional[str]:
    """Horizontal bar: cracked password pattern distribution."""
    if not patterns:
        return None

    with plt.rc_context(plt_style):
        labels = list(patterns.keys())
        counts = [patterns[l]["count"] for l in labels]
        pcts = [patterns[l]["pct"] for l in labels]

        fig, ax = plt.subplots(figsize=(6, max(3, len(labels) * 0.6)))
        pal = ["#ef4444", "#f97316", "#eab308", "#6366f1", "#14b8a6", "#22c55e"]
        bar_colors = [pal[i % len(pal)] for i in range(len(labels))]

        bars = ax.barh(labels, counts, color=bar_colors, edgecolor=BG, linewidth=1)
        for bar, pct, count in zip(bars, pcts, counts):
            ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                    f"{count} ({pct}%)", va="center", fontsize=9)

        ax.set_xlabel("Count of Cracked Devices")
        ax.set_title("Cracked Password Patterns", color=TEXT, fontsize=13)
        ax.set_xlim(0, max(counts, default=1) * 1.4)
        ax.grid(axis="x")
        fig.tight_layout()
        return _fig_to_b64(fig)


# ─────────────────────────────────────────────────────────────────────────────
# HTML Template
# ─────────────────────────────────────────────────────────────────────────────

def _render_html(
    report_data: Dict,
    charts: Dict[str, Optional[str]],
    generated_at: str,
) -> str:
    """
    Render the full HTML report string using Python string formatting.
    No external template engine required.
    """
    devices = report_data["devices"]
    summary = report_data["summary"]
    proto_analysis = report_data.get("protocol_analysis", {})
    pw_patterns = report_data.get("password_patterns", {})
    hardening = report_data.get("hardening_comparison", {})

    def risk_badge(level):
        color = RISK_COLORS.get(level, "#6b7280")
        return (
            f'<span style="background:{color};color:#fff;padding:3px 10px;'
            f'border-radius:12px;font-size:0.78rem;font-weight:700;'
            f'letter-spacing:0.05em">{level}</span>'
        )

    def result_chip(cracked):
        if cracked:
            return '<span style="color:#22c55e;font-weight:700">✓ CRACKED</span>'
        return '<span style="color:#ef4444;font-weight:700">✗ NOT CRACKED</span>'

    def chart_img(b64, alt="Chart", width="100%"):
        if b64:
            return (
                f'<img src="data:image/png;base64,{b64}" '
                f'alt="{alt}" style="width:{width};border-radius:8px;">'
            )
        return '<p style="color:#94a3b8;font-style:italic">Chart unavailable (matplotlib not installed)</p>'

    # ── Device Cards ────────────────────────────────────────────────────────
    device_cards = ""
    for dev in sorted(devices, key=lambda d: -d["risk_score"]):
        recs_html = "".join(
            f'<li style="margin-bottom:6px">{r}</li>'
            for r in dev.get("hardening_recommendations", [])
        )

        attempts_rows = ""
        for i, att in enumerate(dev.get("all_attempts", [])[:50]):  # cap display at 50
            result_color = {
                "AUTH_OK": "#22c55e",
                "AUTH_FAIL": "#94a3b8",
                "LOCKED_OUT": "#ef4444",
                "RATE_LIMITED": "#f97316",
                "ERROR": "#6b7280",
            }.get(att["result"], "#94a3b8")
            attempts_rows += (
                f'<tr style="border-bottom:1px solid #334155">'
                f'<td style="padding:4px 8px;color:#94a3b8;font-size:0.75rem">{i+1}</td>'
                f'<td style="padding:4px 8px;font-family:monospace">{att["username"]}</td>'
                f'<td style="padding:4px 8px;font-family:monospace">{att["password"] or "<empty>"}</td>'
                f'<td style="padding:4px 8px;color:{result_color};font-weight:600">{att["result"]}</td>'
                f'<td style="padding:4px 8px;color:#94a3b8">{att["latency_ms"]:.1f} ms</td>'
                f'</tr>'
            )

        cracked_cred_html = ""
        if dev.get("cracked_credential"):
            c = dev["cracked_credential"]
            cracked_cred_html = (
                f'<div style="background:#14532d;border:1px solid #22c55e;'
                f'border-radius:8px;padding:12px;margin:12px 0;">'
                f'<strong style="color:#22c55e">✓ Cracked Credential</strong><br>'
                f'<code style="color:#86efac">{c["username"]} / {c["password"] or "(empty)"}</code>'
                f'&nbsp;&nbsp;<span style="color:#94a3b8;font-size:0.82rem">'
                f'Rank #{dev.get("cred_rank","?")} in credential list</span>'
                f'</div>'
            )

        bypass_badge = ""
        if dev.get("bypass_attempts", 0) > 0:
            bypass_badge = (
                '<span style="background:#7c3aed;color:#fff;padding:2px 8px;'
                'border-radius:10px;font-size:0.75rem;margin-left:8px">Bypass Attempted</span>'
            )
        lockout_badge = ""
        if dev.get("lockout_detected"):
            lockout_badge = (
                '<span style="background:#1e3a5f;color:#93c5fd;padding:2px 8px;'
                'border-radius:10px;font-size:0.75rem;margin-left:8px">🔒 Lockout Detected</span>'
            )

        device_cards += f"""
        <div style="background:{CARD_BG};border-radius:12px;padding:24px;
                    margin-bottom:20px;border:1px solid #334155;
                    border-left:4px solid {RISK_COLORS.get(dev['risk_level'],'#6b7280')}">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
                <div>
                    <h3 style="margin:0;font-size:1.1rem">{dev['device_id']}</h3>
                    <span style="color:{MUTED};font-size:0.85rem">
                        {dev['device_type'].upper()} · {dev['protocol']} · 
                        127.0.0.1:{dev['port']} ·
                        {'🔒 Hardened' if dev['hardened'] else '⚠ Normal'}
                    </span>
                </div>
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                    {risk_badge(dev['risk_level'])}
                    <span style="font-weight:700;font-size:1rem">Score: {dev['risk_score']}/10</span>
                    {lockout_badge}{bypass_badge}
                </div>
            </div>

            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
                        gap:12px;margin:16px 0;">
                <div style="background:#0f172a;padding:10px 14px;border-radius:8px;text-align:center">
                    <div style="font-size:1.4rem;font-weight:700">{result_chip(dev['cracked'])}</div>
                    <div style="color:{MUTED};font-size:0.75rem;margin-top:2px">Auth Status</div>
                </div>
                <div style="background:#0f172a;padding:10px 14px;border-radius:8px;text-align:center">
                    <div style="font-size:1.4rem;font-weight:700">{dev['attempts']}</div>
                    <div style="color:{MUTED};font-size:0.75rem;margin-top:2px">Attempts</div>
                </div>
                <div style="background:#0f172a;padding:10px 14px;border-radius:8px;text-align:center">
                    <div style="font-size:1.4rem;font-weight:700">
                        {f"{dev['time_to_crack_seconds']:.2f}s" if dev.get('time_to_crack_seconds') else "—"}
                    </div>
                    <div style="color:{MUTED};font-size:0.75rem;margin-top:2px">Time to Crack</div>
                </div>
                <div style="background:#0f172a;padding:10px 14px;border-radius:8px;text-align:center">
                    <div style="font-size:1.4rem;font-weight:700">{dev.get('bypass_attempts',0)}</div>
                    <div style="color:{MUTED};font-size:0.75rem;margin-top:2px">Bypass Attempts</div>
                </div>
            </div>

            {cracked_cred_html}

            <details style="margin-top:12px">
                <summary style="cursor:pointer;color:#6366f1;font-weight:600;
                               padding:8px 0;list-style:none;user-select:none">
                    ▶ View {len(dev.get('all_attempts',[]))} Credential Attempts
                </summary>
                <div style="overflow-x:auto;margin-top:8px">
                    <table style="width:100%;border-collapse:collapse;font-size:0.82rem">
                        <thead>
                            <tr style="background:#0f172a;color:{MUTED}">
                                <th style="padding:6px 8px;text-align:left">#</th>
                                <th style="padding:6px 8px;text-align:left">Username</th>
                                <th style="padding:6px 8px;text-align:left">Password</th>
                                <th style="padding:6px 8px;text-align:left">Result</th>
                                <th style="padding:6px 8px;text-align:left">Latency</th>
                            </tr>
                        </thead>
                        <tbody>{attempts_rows}</tbody>
                    </table>
                </div>
            </details>

            <div style="margin-top:16px">
                <strong style="color:#f97316">🛡 Hardening Recommendations:</strong>
                <ul style="margin:8px 0 0 0;padding-left:20px;color:{TEXT};
                           line-height:1.8;font-size:0.87rem">
                    {recs_html}
                </ul>
            </div>
        </div>
        """

    # ── Protocol Table ───────────────────────────────────────────────────────
    proto_rows = ""
    for proto, stats in proto_analysis.items():
        cr = stats["crack_rate_pct"]
        cr_color = "#ef4444" if cr >= 75 else "#f97316" if cr >= 50 else "#eab308" if cr >= 25 else "#22c55e"
        proto_rows += f"""
        <tr style="border-bottom:1px solid #334155">
            <td style="padding:10px 14px">
                <span style="background:{PROTOCOL_COLORS.get(proto,'#6b7280')};
                             color:#fff;padding:3px 10px;border-radius:10px;font-size:0.8rem">
                    {proto}
                </span>
            </td>
            <td style="padding:10px 14px;text-align:center">{stats['total']}</td>
            <td style="padding:10px 14px;text-align:center;color:#22c55e;font-weight:600">{stats['cracked']}</td>
            <td style="padding:10px 14px;text-align:center;color:{cr_color};font-weight:700">{cr}%</td>
            <td style="padding:10px 14px;text-align:center">
                {f"{stats['avg_attempts_to_crack']}" if stats['avg_attempts_to_crack'] else "—"}
            </td>
            <td style="padding:10px 14px;text-align:center">
                {f"{stats['avg_time_to_crack_s']:.3f}s" if stats['avg_time_to_crack_s'] else "—"}
            </td>
            <td style="padding:10px 14px;font-family:monospace;font-size:0.82rem">
                {stats.get('most_common_cracked_cred') or '—'}
            </td>
        </tr>
        """

    # ── Password Pattern Table ───────────────────────────────────────────────
    pw_rows = ""
    for pattern, info in pw_patterns.items():
        pw_rows += f"""
        <tr style="border-bottom:1px solid #334155">
            <td style="padding:10px 14px;font-weight:600">{pattern.replace('_',' ').title()}</td>
            <td style="padding:10px 14px;text-align:center">{info['count']}</td>
            <td style="padding:10px 14px;text-align:center;font-weight:700;color:#f97316">{info['pct']}%</td>
            <td style="padding:10px 14px;font-family:monospace;font-size:0.82rem">
                {", ".join(f'"{e}"' if e else '"(empty)"' for e in info['examples'])}
            </td>
        </tr>
        """

    # ── Summary cards ────────────────────────────────────────────────────────
    total = summary["total_devices"]
    cracked_n = summary["cracked"]
    crack_pct = round(cracked_n / total * 100) if total else 0
    by_risk = summary.get("by_risk_level", {})

    def stat_card(value, label, color="#e2e8f0"):
        return (
            f'<div style="background:{CARD_BG};border-radius:10px;padding:20px 24px;'
            f'border:1px solid #334155;text-align:center;">'
            f'<div style="font-size:2.2rem;font-weight:800;color:{color}">{value}</div>'
            f'<div style="color:{MUTED};font-size:0.85rem;margin-top:4px">{label}</div>'
            f'</div>'
        )

    harden_normal = hardening.get("normal", {})
    harden_hard = hardening.get("hardened", {})

    hardening_section = ""
    if hardening:
        improvement = harden_normal.get("crack_rate_pct", 0) - harden_hard.get("crack_rate_pct", 0)
        hardening_section = f"""
        <section style="margin-bottom:40px">
            <h2 style="font-size:1.4rem;margin-bottom:16px">🛡 Hardening Effectiveness (Before vs. After)</h2>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px">
                {stat_card(f"{harden_normal.get('crack_rate_pct',0):.0f}%", "Normal Crack Rate", RISK_COLORS['HIGH'])}
                {stat_card(f"{harden_hard.get('crack_rate_pct',0):.0f}%", "Hardened Crack Rate", RISK_COLORS['LOW'])}
                {stat_card(f"↓{improvement:.0f}%", "Improvement", "#6366f1")}
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
                <div style="background:{CARD_BG};border-radius:10px;padding:20px;border:1px solid #334155">
                    {chart_img(charts.get("hardening"), "Hardening Comparison")}
                </div>
                <div style="background:{CARD_BG};border-radius:10px;padding:20px;border:1px solid #334155">
                    <h4 style="margin-top:0">Lockout Bypass Analysis</h4>
                    <p style="color:{MUTED};line-height:1.7;font-size:0.9rem">
                        Hardened devices triggered <strong style="color:{TEXT}">
                        {harden_hard.get('lockout_events',0)} lockout events</strong>.
                        The scanner attempted bypass via timed retry (exponential backoff).
                        <strong style="color:{TEXT}">{harden_hard.get('bypass_successes',0)}</strong> 
                        bypasses succeeded — demonstrating that simple timeout-based lockouts
                        can be circumvented without CAPTCHA or IP-ban enforcement.
                    </p>
                    <p style="color:{MUTED};line-height:1.7;font-size:0.9rem">
                        <strong style="color:#f97316">Recommendation:</strong> Lockout alone is 
                        insufficient. Combine with exponential delay, CAPTCHA for repeated failures,
                        and permanent IP bans after N bypass attempts.
                    </p>
                </div>
            </div>
        </section>
        """

    # ── Assemble final HTML ──────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Credential Scan Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after {{ box-sizing: border-box; }}
        body {{
            margin: 0; background: {BG}; color: {TEXT};
            font-family: 'Inter', -apple-system, sans-serif;
            line-height: 1.6; font-size: 0.95rem;
        }}
        a {{ color: #6366f1; }}
        code, pre {{ font-family: 'JetBrains Mono', monospace; }}
        details > summary::-webkit-details-marker {{ display: none; }}
        details[open] > summary {{ margin-bottom: 8px; }}
        details[open] > summary::before {{ content: "▼ "; }}
        details:not([open]) > summary::before {{ content: "▶ "; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 0 24px 60px; }}
        .hero {{
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
            border-bottom: 1px solid #334155;
            padding: 40px 0 32px;
            margin-bottom: 40px;
        }}
        .hero-inner {{ max-width: 1100px; margin: 0 auto; padding: 0 24px; }}
        .tag {{
            display: inline-block; background: #1e293b; border: 1px solid #334155;
            padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; color: {MUTED};
            margin-right: 6px; margin-bottom: 4px;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #0f172a; color: {MUTED}; font-weight: 600; text-align: left; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media(max-width: 700px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>

<div class="hero">
    <div class="hero-inner">
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
            <div style="font-size:2.5rem">🔍</div>
            <div>
                <h1 style="margin:0;font-size:1.9rem;font-weight:800;
                           background:linear-gradient(90deg,#6366f1,#ec4899);
                           -webkit-background-clip:text;-webkit-text-fill-color:transparent">
                    IoT Default Credential Scanner
                </h1>
                <p style="margin:4px 0 0;color:{MUTED};font-size:0.9rem">
                    Security Analysis Report — Simulated IoT Network
                </p>
            </div>
        </div>
        <div>
            <span class="tag">Educational Research</span>
            <span class="tag">Localhost Only</span>
            <span class="tag">Mirai Simulation</span>
            <span class="tag">Default Credentials</span>
        </div>
        <p style="color:{MUTED};font-size:0.82rem;margin-top:12px;margin-bottom:0">
            Generated: {generated_at} &nbsp;|&nbsp; 
            This report simulates the credential-stuffing technique used by the Mirai botnet (2016).
            All scanning was performed on localhost simulated devices — no real IoT hardware involved.
        </p>
    </div>
</div>

<div class="container">

    <!-- Executive Summary -->
    <section style="margin-bottom:40px">
        <h2 style="font-size:1.4rem;margin-bottom:16px">📊 Executive Summary</h2>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:20px">
            {stat_card(total, "Devices Scanned")}
            {stat_card(cracked_n, "Devices Cracked", RISK_COLORS['HIGH'])}
            {stat_card(f"{crack_pct}%", "Overall Crack Rate", RISK_COLORS['CRITICAL'] if crack_pct>=75 else RISK_COLORS['HIGH'] if crack_pct>=50 else RISK_COLORS['MEDIUM'])}
            {stat_card(by_risk.get('CRITICAL',0), "CRITICAL Risk", RISK_COLORS['CRITICAL'])}
            {stat_card(by_risk.get('HIGH',0), "HIGH Risk", RISK_COLORS['HIGH'])}
            {stat_card(by_risk.get('LOW',0), "LOW Risk (Hardened)", RISK_COLORS['LOW'])}
        </div>

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px">
            <div style="background:{CARD_BG};border-radius:10px;padding:20px;border:1px solid #334155">
                {chart_img(charts.get("risk_donut"), "Risk level donut chart")}
            </div>
            <div style="background:{CARD_BG};border-radius:10px;padding:20px;border:1px solid #334155">
                {chart_img(charts.get("protocol_bars"), "Protocol vulnerability bar chart")}
            </div>
        </div>
    </section>

    <!-- Timing Analysis -->
    <section style="margin-bottom:40px">
        <h2 style="font-size:1.4rem;margin-bottom:16px">⏱ Scan Timing Analysis</h2>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
            <div style="background:{CARD_BG};border-radius:10px;padding:20px;border:1px solid #334155">
                {chart_img(charts.get("time_hist"), "Time to crack histogram")}
            </div>
            <div style="background:{CARD_BG};border-radius:10px;padding:20px;border:1px solid #334155">
                {chart_img(charts.get("attempts_cdf"), "Attempts to crack CDF")}
            </div>
        </div>
    </section>

    <!-- Hardening Comparison -->
    {hardening_section}

    <!-- Password Pattern Analysis -->
    <section style="margin-bottom:40px">
        <h2 style="font-size:1.4rem;margin-bottom:16px">🔑 Password Pattern Analysis</h2>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
            <div style="background:{CARD_BG};border-radius:10px;padding:20px;border:1px solid #334155">
                {chart_img(charts.get("pw_patterns"), "Password patterns chart")}
            </div>
            <div style="background:{CARD_BG};border-radius:10px;padding:20px;border:1px solid #334155">
                <table>
                    <thead>
                        <tr><th style="padding:8px 12px">Pattern</th>
                            <th style="padding:8px 12px;text-align:center">Count</th>
                            <th style="padding:8px 12px;text-align:center">%</th>
                            <th style="padding:8px 12px">Examples</th></tr>
                    </thead>
                    <tbody>{pw_rows if pw_rows else '<tr><td colspan="4" style="padding:12px;color:#94a3b8">No cracked credentials to analyze</td></tr>'}</tbody>
                </table>
            </div>
        </div>
    </section>

    <!-- Protocol Vulnerability Table -->
    <section style="margin-bottom:40px">
        <h2 style="font-size:1.4rem;margin-bottom:16px">🌐 Protocol Vulnerability Analysis</h2>
        <div style="background:{CARD_BG};border-radius:10px;border:1px solid #334155;overflow:hidden">
            <table>
                <thead>
                    <tr>
                        <th style="padding:12px 14px">Protocol</th>
                        <th style="padding:12px 14px;text-align:center">Total</th>
                        <th style="padding:12px 14px;text-align:center">Cracked</th>
                        <th style="padding:12px 14px;text-align:center">Crack Rate</th>
                        <th style="padding:12px 14px;text-align:center">Avg Attempts</th>
                        <th style="padding:12px 14px;text-align:center">Avg Time</th>
                        <th style="padding:12px 14px">Most Common Cred</th>
                    </tr>
                </thead>
                <tbody>{proto_rows if proto_rows else '<tr><td colspan="7" style="padding:12px;color:#94a3b8">No data</td></tr>'}</tbody>
            </table>
        </div>
    </section>

    <!-- Per-Device Results -->
    <section style="margin-bottom:40px">
        <h2 style="font-size:1.4rem;margin-bottom:16px">📱 Per-Device Risk Assessment</h2>
        {device_cards if device_cards else '<p style="color:#94a3b8">No device results available.</p>'}
    </section>

    <!-- Methodology -->
    <section style="margin-bottom:40px;background:{CARD_BG};border-radius:12px;
                    padding:28px;border:1px solid #334155">
        <h2 style="font-size:1.3rem;margin-top:0">📋 Methodology & Context</h2>
        <h4 style="color:#6366f1">Simulation Architecture</h4>
        <p style="color:{MUTED};font-size:0.9rem;line-height:1.8">
            Four device types (IPCamera, Router, IoT Sensor, Smart Plug) were simulated as
            TCP servers on localhost ports 9001–9008. Each type implements a distinct 
            authentication protocol. Devices run in two modes: <em>normal</em> (no lockout) and
            <em>hardened</em> (lockout after 5 failures within 60 seconds).
        </p>
        <h4 style="color:#6366f1">Credential Dataset</h4>
        <p style="color:{MUTED};font-size:0.9rem;line-height:1.8">
            The credential list is curated from the <strong style="color:{TEXT}">Mirai botnet 
            source code</strong> (published 2016, ~60 default pairs) and 
            <strong style="color:{TEXT}">OWASP/SecLists default-passwords</strong>. 
            Credentials are ranked by real-world prevalence. All credentials are publicly 
            documented in security research literature.
        </p>
        <h4 style="color:#6366f1">Risk Scoring Rubric</h4>
        <table style="font-size:0.85rem">
            <thead><tr>
                <th style="padding:8px 12px">Condition</th>
                <th style="padding:8px 12px;text-align:center">Score</th>
                <th style="padding:8px 12px">Level</th>
            </tr></thead>
            <tbody>
                <tr><td style="padding:7px 12px">Cracked with empty password</td>
                    <td style="padding:7px 12px;text-align:center">9</td>
                    <td style="padding:7px 12px">{risk_badge('CRITICAL')}</td></tr>
                <tr><td style="padding:7px 12px">Cracked with top-5 credential</td>
                    <td style="padding:7px 12px;text-align:center">10</td>
                    <td style="padding:7px 12px">{risk_badge('CRITICAL')}</td></tr>
                <tr><td style="padding:7px 12px">Cracked with top-20 credential</td>
                    <td style="padding:7px 12px;text-align:center">8</td>
                    <td style="padding:7px 12px">{risk_badge('HIGH')}</td></tr>
                <tr><td style="padding:7px 12px">Lockout bypassed, then cracked</td>
                    <td style="padding:7px 12px;text-align:center">7</td>
                    <td style="padding:7px 12px">{risk_badge('HIGH')}</td></tr>
                <tr><td style="padding:7px 12px">Cracked after 20+ attempts</td>
                    <td style="padding:7px 12px;text-align:center">6</td>
                    <td style="padding:7px 12px">{risk_badge('HIGH')}</td></tr>
                <tr><td style="padding:7px 12px">Not cracked, no lockout enforced</td>
                    <td style="padding:7px 12px;text-align:center">4</td>
                    <td style="padding:7px 12px">{risk_badge('MEDIUM')}</td></tr>
                <tr><td style="padding:7px 12px">Not cracked, lockout enforced</td>
                    <td style="padding:7px 12px;text-align:center">2</td>
                    <td style="padding:7px 12px">{risk_badge('LOW')}</td></tr>
            </tbody>
        </table>
    </section>

    <footer style="text-align:center;color:{MUTED};font-size:0.8rem;border-top:1px solid #334155;padding-top:20px">
        IoT Default Credential Scanner · Educational Security Research · 
        All scanning was performed on localhost simulated devices only ·
        Generated {generated_at}
    </footer>

</div>
</body>
</html>"""
    return html


# ─────────────────────────────────────────────────────────────────────────────
# Public Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(report_data: Dict, output_path: str) -> str:
    """
    Generate a self-contained HTML security report with embedded charts.

    Args:
        report_data: Output from risk_report.generate_full_report_data()
        output_path: Absolute path to write the HTML file.

    Returns:
        Absolute path to the generated report file.
    """
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Generate all charts
    charts = {}
    if HAS_MATPLOTLIB:
        print("  [+] Generating charts...")
        charts["risk_donut"] = _chart_risk_donut(
            report_data.get("summary", {}).get("by_risk_level", {})
        )
        charts["protocol_bars"] = _chart_protocol_bars(
            report_data.get("protocol_analysis", {})
        )
        charts["time_hist"] = _chart_time_to_crack(report_data.get("devices", []))
        charts["attempts_cdf"] = _chart_attempts_cdf(report_data.get("devices", []))
        charts["hardening"] = _chart_hardening_comparison(
            report_data.get("hardening_comparison", {})
        )
        charts["pw_patterns"] = _chart_password_patterns(
            report_data.get("password_patterns", {})
        )
    else:
        print("  [!] matplotlib not installed — charts will be omitted from report.")

    html = _render_html(report_data, charts, generated_at)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
