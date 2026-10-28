# ZeroSentinel demo script (about 5 minutes)

Runs entirely on sample data. Start with `npm run dev`, open http://localhost:5173/?reset=1
(fresh data), and keep the window at least 1366 px wide.

1. **Dashboard.** "58 findings across 3 scans, 18 of them Novel: only our ML model caught them."
   Point at the severity donut, the OWASP 2025 bars and the **False positives suppressed: 2** tile.
   Click **A05 Injection** in the bars: it opens the latest scan's findings, filtered.

2. **Findings** (`acme-shop-v1.5.zip`). Show the **Compared with previous scan** strip
   (+11 new, −3 resolved, 2 suppressed by feedback). Click **Clear filters**, then the
   **Source** dropdown → **ML only (Novel)** to show the zero-day candidates.

3. **Finding detail.** Open **Server fetches a user-supplied URL** (the `app/webhooks/dispatch.py` one).
   Show the highlighted sink line, the risk gauge, **Detected by** (no rule matched, ML 82%),
   the CWE/OWASP links and the markdown fix. Press `]` and `[` to move between findings.

4. **Teach the model.** Under **Triage & status** click **False positive**. Try **Confirm** with no
   reason: it's refused. Pick **Test or example code**, keep **Use this to improve the model**
   ticked, **Confirm**. The banner now reads _Score lowered by feedback: 0.82 → 0.29 · model v1.3_.

5. **Re-scan.** **Back to findings** → **Re-scan**. The New Scan page plays the 20-second run:
   four stages, live findings feed. When it finishes, the summary card shows
   **Compared with previous scan** with 3 suppressed by feedback.

6. **Scan changes.** Click **View changes**. Under **Suppressed by feedback** the webhook finding now
   sits with _0.82 → 0.29, learned in v1.3_ and its reason. Point out that rule-only findings
   never get suppressed.

7. **Model.** Sidebar → **Model**. Model card, held-out vulnerability types (types the model never
   saw in training), and **Learning from feedback**: v1.3 at the top of the version timeline.
   Optionally click **Revert** on v1.2 → confirm, to show feedback can be undone.

8. **Fresh scan.** **New scan** → **Run demo scan** (a small vulnerable Flask app sent as text,
   never executed). Watch 15 findings stream in over 20 seconds.

9. **Report.** Sidebar → **Reports**. Pick the scan, show the sandboxed preview and click
   **Download PDF**.

If anything goes wrong mid-demo: **Reset sample data** at the bottom of the sidebar.
