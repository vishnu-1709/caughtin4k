# CaughtIn4K — Master Prompt for Claude Code

You are my build partner for a **24-hour solo cybersecurity hackathon**. Read this whole file and the problem statement PDF (if attached) before doing anything. **Work autonomously.** Only stop when you genuinely need me, using the rules in section 0.

---

## 0. Working protocol (most important section)

### Two kinds of checkpoints
- **📣 Report and continue:** after finishing a phase or a detector, post a short status (what was built, how it was tested, the test output in 2–3 lines, time left) and **keep going without waiting.**
- **🛑 Stop and wait:** only for things that truly need me. Stop, tell me **exactly** what to do (numbered steps, exact commands or clicks), and wait for my reply before continuing.

### Stop (🛑) only for these
1. Something only I can do: creating the GitHub repo or logging in (`git push`, `gh auth`), deploying on Streamlit Community Cloud, recording the video, submitting the Google Form, installing software on my machine.
2. Visual review: the full UI (Phase F) and the deployed site (Phase H2). I check it in my browser.
3. Cutting scope, adding a dependency not listed in section 2, or changing the theme or UI design.
4. Something failed twice and you can't fix it.
5. Final submission check (Phase K).

Everything else (file structure, internal design, thresholds, helper functions, test data, fixing your own bugs), decide yourself and continue.

### While working
- **Teach as you go, without stopping.** Before writing each detector or core engine file, write a short explanation (3–6 lines): the networking concept, the rule used, and why. I want to learn from this, so never skip it, but don't wait for a reply.
- **Small steps, always tested.** One file or detector at a time. Run it on its sample before moving on.
- **Time awareness.** The hard deadline is **Sunday 01/11/2026, 21:00 IST**. Run `date` at every 📣 and include: time left, current phase, on schedule or behind. If behind by more than 30 minutes, 🛑 and propose cuts using the priority list in section 9.
- **Commit to git after every 📣** with a clear message. Never commit secrets. Nothing may be committed after the deadline.
- **When you need something from me,** start the message with **"🛑 ACTION NEEDED"** so I spot it instantly, and say what happens after I reply.
- **Keep messages short and direct.** No fluff.

---

## 1. The problem (from the official statement)

**Track:** Network — *Diagnosing Network Problems from Packet Captures.*

Small offices, labs and campus departments have no network or security person. When the network is slow, drops connections or behaves strangely, finding the cause means reading a packet capture line by line, which needs deep protocol knowledge. It is even harder to tell a harmless fault from an attack hiding in the same traffic.

**Build a tool that takes a packet capture file as input, finds the faults and attacks in the traffic, and explains them in plain language with the likely cause and a suggested fix.**

### Challenge points (all must be addressed)
- **F1 Reading captures safely:** large, broken or malicious files must not crash the tool or leak data.
- **F2 Finding faults:** TCP retransmissions and resets, DNS failures, duplicate IP addresses, ARP conflicts, MTU mismatches, unusual delays.
- **F3 Finding attacks:** port scans, ARP spoofing, DNS hijacking, rogue DHCP servers.
- **F4 Telling an outage from an attack:** separate plain faults from malicious activity; keep false alarms low.
- **F5 Explaining clearly:** beginner-readable language.
- **F6 Recommending fixes:** likely cause + practical next step for **every** problem.
- **F7 Showing the evidence:** exact packets/conversations behind each diagnosis, with a timeline or summary view.

### Rules that constrain the build
- Built entirely during the hackathon (Sat 31/10 21:00 → Sun 01/11 21:00 IST). Solo team.
- **Detection and diagnosis logic must be our own.** Scapy/PyShark for *reading* captures is allowed. Wrapping Wireshark/tshark output does **not** count.
- List **every** open-source library used in the README.
- Include sample captures in the repo so judges can run it without a network.
- Test only on sample/self-generated captures or networks I own. Never capture others' traffic.
- Validate all input, protect user data, no hardcoded secrets.
- **Faked or misleading demo = disqualification.** Everything shown must really run.
- **Submission:** public GitHub repo + 2–5 min demo video (in repo or linked in README; GitHub blocks files >100 MB) + README (problem, solution, features, setup).

### Judging
| Criterion | Weight | What it means for us |
|---|---|---|
| Novelty | 20% | different from existing tools → fault-vs-attack reasoning, incident grouping, beginner UX |
| Technical implementation | 30% | own detection logic, code quality, structure, edge cases |
| Security of the solution | 20% | safe input handling, no data leaks, no secrets |
| Feasibility | 10% | practical, reliable, easy setup from README |
| Video presentation | 20% | clear demo of problem, solution, key features |

---

## 2. Solution overview

**CaughtIn4K**: a **Streamlit website** (beginner-friendly), deployed publicly on **Streamlit Community Cloud** so judges can open it in a browser, and also runnable locally for people who don't want to upload captures. A **CLI** shares the same engine.

```
pcap file → safe loader → detectors (one pass) → judge (fault/attack/uncertain)
          → grouping (incidents + causal links) → UI / CLI / JSON / HTML report
```

- The tool **never touches the network it analyses.** It only reads saved capture files. No live capture, no outbound network calls, no telemetry.
- **Hosted privacy rule:** uploaded files go to a temporary file, are analysed, and are **deleted immediately** (in a `finally` block). Nothing is stored, cached to disk or logged. The UI says so plainly.
- Language: **Python 3.10+**. Libraries: `scapy` (parsing only), `streamlit`, `pandas`, `altair` (ships with Streamlit). Ask me before adding anything else.

### Repository structure
```
caughtin4k/
  engine/
    __init__.py
    findings.py        # Finding + Incident dataclasses (shared format)
    loader.py          # safe validation + streaming parse
    context.py         # shared state: devices, gateway, DNS/DHCP servers, baselines
    detectors/
      __init__.py      # detector registry
      base.py          # Detector interface
      arp.py           # ARP spoofing + duplicate IP + ARP conflicts
      tcp_retrans.py
      tcp_reset.py
      dns_failures.py
      dns_hijack.py
      port_scan.py
      rogue_dhcp.py
      delays.py
      mtu.py
    judge.py           # fault vs attack scoring
    grouping.py        # incidents + causal chains
    explain.py         # plain-language text, fixes, benign alternatives
    report.py          # JSON + escaped HTML report
    analyze.py         # one function: analyze(path, options) -> Result
  app.py               # Streamlit UI
  cli.py               # CLI
  generate_samples.py  # crafts labelled sample captures with Scapy
  evaluate.py          # runs engine on all samples, prints detected vs expected
  samples/             # generated .pcap files + labels.json
  tests/               # small pytest tests per detector
  .streamlit/config.toml
  requirements.txt     # pinned versions
  README.md
  LICENSE
```

---

## 3. Core data format (build this first)

Every UI card, CLI line and report entry is one `Finding`. The format forces F5, F6 and F7 to always be present.

```python
@dataclass
class Finding:
    id: str
    kind: str                 # e.g. "arp_spoofing", "duplicate_ip", "tcp_retransmissions"
    category: str             # "attack" | "fault"  (what the detector looks for)
    verdict: str              # "attack" | "fault" | "uncertain" (set by judge)
    confidence: str           # "low" | "medium" | "high"  (no fake percentages)
    title_simple: str         # "Someone is pretending to be your router"
    title_technical: str      # "ARP spoofing of gateway 192.168.1.1"
    explanation: str          # plain-language what happened
    indicators_for: list[str]   # evidence pointing to attack
    indicators_against: list[str] # evidence pointing to harmless fault
    benign_alternative: str   # "Could also be a replaced router — check if…"
    likely_cause: str
    fix_steps: list[str]      # numbered, specific actions
    evidence_frames: list[int]  # Wireshark-compatible numbering, starts at 1
    hosts: list[str]          # IPs/MACs involved
    time_start: float
    time_end: float
    wireshark_filter: str     # copyable display filter to verify in Wireshark
    details: dict             # detector-specific numbers (counts, rates, etc.)
```

`Incident` groups related findings: `id, findings, verdict, summary, caused_by (optional link)`.

**Detector interface:**
```python
class Detector:
    name: str
    def feed(self, pkt, frame_no: int, ts: float, ctx: Context) -> None: ...
    def finish(self, ctx: Context) -> list[Finding]: ...
```
`finish()` exists because some problems are only known at the end (e.g. a DNS query that never got a reply). Every detector must **cap its stored state** (max tracked flows/entries) so huge captures can't exhaust memory.

---

## 4. Safe loader (F1, Security 20%)

- Check file size against a limit (default **50 MB**, configurable; free hosting has limited memory) **before** parsing.
- Check **magic bytes**: accept only pcap (`d4 c3 b2 a1`, `a1 b2 c3 d4`, nanosecond variants) and pcapng (`0a 0d 0d 0a`). Reject everything else with a friendly message.
- Stream with `PcapReader` (never `rdpcap`, which loads everything into memory).
- Wrap each packet's processing in try/except: skip, count, continue. Never crash on one bad packet.
- Handle a truncated file: stop cleanly, analyse what was read, warn.
- Cap total packets and wall-clock time; on hitting a cap, return **partial results with a warning**.
- Run parsing in a **subprocess with a timeout** so a hang in a dissector can't freeze the app.
- Handle captures with no Ethernet layer (Linux cooked/SLL, raw IP) and Wi-Fi monitor captures: skip checks that need MACs, tell the user which checks were skipped.
- Uploads in the UI: process from a temporary file that is always deleted afterwards, even on errors. Don't keep uploaded bytes in `st.session_state` longer than needed.
- Never write capture contents to logs. No network calls anywhere.
- **All text that reaches HTML must be escaped** (packet fields like DNS names can contain `<script>`).
- `--redact` / "Hide IPs" option masks IPs and MACs consistently (same real value → same mask) in UI and exports.
- Output paths are sanitised (no path traversal).

---

## 5. Detectors: concept and rules

Before each detector: explain the concept in plain words, then implement. Thresholds live in one config dict, not scattered constants. "Unusual" means relative to the capture's own baseline (median) **and** above an absolute floor.

### Faults
- **TCP retransmissions:** same flow (5-tuple), same sequence number, payload length > 0, seen again. Ignore keepalives (0/1-byte segments) and zero-window probes. Report rate per flow; flag flows above a threshold.
- **TCP resets:** count RSTs per flow and per server. RST right after SYN = closed port. Many clients getting RST from one server = service down (fault). One source getting RSTs from many ports = scan signal (pass to port scan / judge).
- **DNS failures:** match queries to responses by (client, server, transaction ID). No reply within ~2 s = timeout. Count SERVFAIL / NXDOMAIN / REFUSED rates.
- **Duplicate IP / ARP conflicts:** one IP claimed by more than one MAC. Shares logic with ARP spoofing; the **judge** decides fault vs attack.
- **Unusual delays:** SYN → SYN-ACK time per connection and DNS response time; flag outliers (> 3× capture median and > absolute floor).
- **MTU mismatch:** ICMP type 3 code 4 ("fragmentation needed"), or large DF-set packets repeatedly retransmitted while small packets on the same flow succeed. **Ignore segments larger than the link MTU seen in host captures (NIC offloading, TSO/GRO); report "offloading likely" instead of an MTU fault.** Tier 3 — build only if time allows.

### Attacks
- **Port scan:** within a sliding time window, one source contacting many distinct destination ports or hosts, mostly SYN with RST or no reply, few completed handshakes.
- **ARP spoofing:** IP→MAC mapping changes; unsolicited ARP replies (no matching request); repeated replies; gateway IP claimed by a new MAC; one MAC claiming multiple IPs including the gateway.
- **DNS hijacking:** response from a server the client did not query; two responses to the same query ID with different answers; public domain resolving to a private/reserved IP; DNS server differs from the one DHCP handed out.
- **Rogue DHCP:** OFFER/ACK from more than one DHCP server ID; different router/DNS options between servers.

### Context (shared, built during the same pass)
Devices table (IP, MAC, vendor from Scapy's built-in `conf.manufdb`, "Unknown" if missing), inferred gateway, DNS servers, DHCP servers, capture start/end, link type, packet/skip counts, signs of capture loss (ACKs for data never seen, connections starting mid-stream).

---

## 6. Judge, grouping, explanations (F4, F5, F6, Novelty)

**Judge:** rule-based scoring per finding using explicit indicators.
- Example for an IP claimed by two MACs — attack indicators: gateway IP involved, unsolicited replies, high repetition rate, new MAC also claims its own IP. Fault indicators: sporadic, replies follow requests, both MACs have normal traffic.
- Output `attack` / `fault` / **`uncertain` (a real outcome when evidence is mixed)**, plus `confidence` low/medium/high, and the indicators that fired on both sides.

**Grouping:** findings that overlap in time and share hosts → one incident. Two explicit causal rules:
1. Rogue DHCP + DNS answers from the rogue-advertised server → one incident, "rogue DHCP caused DNS hijack".
2. ARP spoofing + retransmission/delay spike on the same hosts → "spoofing likely caused the slowdown".
No other correlation.

**Explanations (`explain.py`):** template-based, offline. Each kind has a simple title, technical title, explanation, likely cause, numbered fix steps, benign alternative ("could also be router failover — check whether…"). Simple wording by default; technical wording when the user switches mode. Fixes must be specific and must not give dangerous confident advice when the verdict is uncertain.

---

## 7. UI specification (Streamlit)

Principle: **answer first, details on demand.** A beginner must understand the situation within 3 seconds without scrolling.

### Theme — "Calm operator" (finalised, do not change without asking)
`.streamlit/config.toml`:
```toml
[theme]
base = "dark"
primaryColor = "#2DD4BF"
backgroundColor = "#0B1220"
secondaryBackgroundColor = "#111A2E"
textColor = "#E2E8F0"
font = "sans-serif"
codeFont = "monospace"
baseRadius = "small"
borderColor = "#1F2A44"
showWidgetBorder = true

[server]
maxUploadSize = 50
```
Do **not** set `server.address` in the committed config: it breaks hosting. In the README, tell local users to run `streamlit run app.py --server.address 127.0.0.1` to keep it local-only.
Verify each option against the installed Streamlit version; if one isn't supported, pick the nearest equivalent and mention it in the next 📣.

Colour is used **only for meaning:** attack `#F04438` red, fault `#F79009` amber, healthy `#12B76A` green, uncertain `#98A2B3` grey, accent `#2DD4BF` teal, muted text `#94A3B8`. Sans-serif for plain-language text; **monospace for everything technical** (IPs, MACs, frame numbers, filters). No glow, gradients, neon or decorative animations.

### Layout (top to bottom)
1. **Header:** name "CaughtIn4K", one-line tagline, privacy note: "Your file is analysed and deleted immediately. Nothing is stored."
2. **Input row:** drag-and-drop upload (.pcap/.pcapng/.cap, limit shown) + "Or try a sample" dropdown with a one-line description per sample. "How to record a capture" expander (3 steps with Wireshark).
3. **File preview** before analysis: name, size, packet count, duration.
4. **Progress bar** with packet count while parsing.
5. **Verdict banner:** "Under attack: 1 attack, 2 faults found" (red) / "Needs attention" (amber) / "Network looks healthy" (green). One line saying where to start.
6. **Metrics row:** packets read, skipped packets, devices, duration.
7. **Coverage note:** what this capture can and can't show; warnings for suspected capture loss, mid-stream start, skipped checks.
8. **Controls:** filter All / Attacks / Faults (with counts), "Hide IPs" toggle, Simple / Technical wording switch.
9. **Issue cards,** sorted attack → fault → uncertain, then confidence. Each card:
   - coloured verdict badge + confidence, simple title, time range
   - one-line explanation (devices shown with vendor, e.g. "Raspberry Pi")
   - **What to do** — numbered fix steps (always visible)
   - expanders: **Why we think so** (indicators for/against), **Could it be harmless?**, **Evidence** (packet table: frame, time, source, destination, protocol, info — sortable/searchable)
   - Wireshark filter in `st.code` (copy button) + "Linked: caused by / caused…" if part of a chain
10. **Timeline chart:** issues over time, coloured by verdict.
11. **Devices table:** IP, MAC, vendor, role (gateway / DNS / DHCP server / impostor), highlighted if involved in an attack.
12. **Capture stats:** protocols breakdown, top talkers.
13. **Downloads:** HTML report (escaped), JSON, evidence CSV.

### Errors and empty states (never a stack trace)
- Wrong type: "This isn't a packet capture (.pcap or .pcapng). Try a sample instead."
- Too big: "This file is over 50 MB. Record a shorter capture, or run CaughtIn4K locally for bigger files."
- Empty: "This capture has no packets."
- Unsupported link type: "Some checks were skipped because this capture has no device (MAC) information."
- No issues: "Network looks healthy" + coverage note.
- No file yet: show the capture guide and the sample dropdown.

### CLI
`python cli.py capture.pcap [--json] [--redact] [-o report.html]` → short summary in the terminal. Exit codes: 0 healthy, 1 faults, 2 attacks.

---

## 8. Samples, evaluation, README, video

**`generate_samples.py`** (Scapy, deterministic seed) creates one capture per scenario, each with **background noise traffic** so detection isn't trivially easy:
`clean.pcap`, `arp_spoof.pcap`, `duplicate_ip.pcap`, `port_scan.pcap`, `rogue_dhcp_dns_hijack.pcap`, `dns_failures.pcap`, `tcp_retransmissions.pcap`, `tcp_resets_service_down.pcap`, `slow_handshakes.pcap`, `mtu.pcap` (if built), `mixed_attack_and_fault.pcap`, `malicious_xss_dnsname.pcap` (DNS name containing `<script>` — must render harmlessly), `broken_truncated.pcap`, `not_a_pcap.pcap` (wrong magic bytes).
Write `samples/labels.json` with the expected findings per file.

**`evaluate.py`:** runs the engine on every sample, prints a table of expected vs detected, false positives, and verdict correctness. `clean.pcap` must produce zero attack findings. Put the table in the README. Be honest that synthetic samples prove less than real traffic.

**README.md:** problem, solution, how it differs from existing tools (fault-vs-attack reasoning with indicators, incidents with causal links, beginner UX, safety), features, screenshots, **live site link at the top**, local setup (`pip install -r requirements.txt` → `streamlit run app.py --server.address 127.0.0.1`, plus CLI usage), privacy (what happens to uploaded files), architecture diagram, detection rules summary, security measures, evaluation table, **known limitations** (single capture point visibility, encrypted DNS/QUIC, IPv6 not covered, slow scans, MAC cloning, synthetic samples), list of every library with licence, responsible-use note, demo video link.

**Video (2–5 min), I will record it; you draft the script:**
problem in 15 s → load the mixed sample → verdict banner → attack card (fix, why, evidence, Wireshark filter) → duplicate-IP sample judged as fault vs ARP-spoof judged as attack (same symptom, different verdict) → malicious file handled safely → evaluation table → close.

---

## 9. Phases, checkpoints and priorities

Current status: **starting from zero**. Check the time first and rescale this plan to the time actually left.

| Phase | Work | Checkpoint |
|---|---|---|
| A | Local repo setup, `requirements.txt` (pinned), `.gitignore`, git init, theme config, folder structure, venv + install | 📣 tree + install output |
| B | `findings.py`, `context.py`, `loader.py` (with all safety checks), `analyze.py` skeleton | 📣 loader rejects bad files, streams a good one, prints counts |
| C | Sample generator for ARP spoof + duplicate IP + clean | 📣 sample summaries (packet counts, what's inside) |
| D | ARP detector + judge for ARP + minimal `app.py` showing raw findings | 📣 **end-to-end works:** spoof → attack, duplicate → fault, clean → nothing |
| D2 | **Early deploy.** Prepare the repo for hosting, then guide me through creating the public GitHub repo, pushing, and deploying on share.streamlit.io (numbered steps) | 🛑 I create the repo, push, deploy, and send you the live URL |
| E | Tier 1 detectors one by one: port scan, TCP resets, retransmissions, DNS failures, rogue DHCP (each with its sample + test) | 📣 per detector |
| F | Full UI per section 7 (banner, cards, expanders, evidence tables, filters, redact, wording switch) | 🛑 I review the UI in my browser (tell me what to click and check) |
| G | Tier 2: DNS hijack, delays; grouping + causal rules; timeline; devices table | 📣 |
| H | Exports (JSON, escaped HTML, CSV), CLI, malicious/broken samples verified, subprocess timeout | 📣 |
| H2 | Push and redeploy; check the live site with every sample, an upload and a bad file | 🛑 I confirm the live site works |
| I | `evaluate.py`, tests, Tier 3 MTU if time allows | 📣 evaluation table |
| J | README (live link at top), limitations, library list, video script | 🛑 I review README + script, then record the video |
| K | Fresh-clone test following README exactly, final push before 21:00, submission checklist (repo link, video link, live link) | 🛑 final go; I submit the Google Form |

**After D2, push to GitHub after every 📣** so the live site always reflects the latest working version. If a push fails because of authentication, 🛑 and tell me what to run.

**Priority if time runs short (ask me before cutting):**
Never cut: safe loader, Finding format, Tier 1 detectors, judge, verdict banner, issue cards with fixes and evidence, sample captures, README, working demo.
Cut first, in this order: MTU detector → wording switch → top talkers/protocol stats → HTML report (keep JSON) → timeline → causal grouping.

Target timing (IST): end-to-end (Phase D) by ~13:00, deployed (D2) by ~13:30, Tier 1 done by ~15:30, UI done by ~17:00, submission-ready by ~19:30, buffer until 21:00.

---

## 10. Code quality rules
- Type hints and short docstrings on public functions. Small functions. No dead code.
- Each detector has at least one pytest test using a generated sample.
- Clear user-facing error messages; internal errors logged without packet contents.
- No secrets, keys or personal data in the repo. Add a `.gitignore` (venv, caches, user captures except `samples/`).

---

## 11. Deployment notes (Streamlit Community Cloud)
- The app entry point is `app.py` at the repo root. `requirements.txt` must contain everything needed to run it.
- Samples must be committed so the live site can load them.
- Free hosting has limited memory and can put the app to sleep when idle. Keep packet and time caps strict, and remind me before judging and before recording the video to open the live link first.
- Never add secrets; the app needs none.

---

**Start now:** run `date`, post a 5-line rescaled plan as a 📣, then start Phase A immediately without waiting.
