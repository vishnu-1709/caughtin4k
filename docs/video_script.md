# CaughtIn4K demo video script (target 4:00, hard limit 5:00)

**Before recording:** open <https://caughtin4k.streamlit.app/> 5 minutes early and load one sample, because the free host
sleeps when idle. Use a 1280-wide browser window at 100% zoom. Close other tabs. Speak slowly.

---

### 0:00 – 0:20 · The problem (home page)

> "When the network breaks in a small office or a college lab, nobody there can read a packet capture. And a
> harmless fault and an attack look exactly the same to a user: 'the internet is broken'. CaughtIn4K fixes that."

*Point at:* the tagline and the privacy line.

### 0:20 – 0:35 · What it checks (still on home)

> "You upload a capture from Wireshark. CaughtIn4K runs eleven checks, four kinds of attack and seven kinds of
> fault, all with our own detection logic. Scapy only reads the packets."

*Point at:* the "What CaughtIn4K checks" block.

### 0:35 – 1:35 · A real attack story (Multi-step → `attack_chain.pcap`)

*Action:* click **Multi-step**, choose `attack_chain.pcap`.

> "In three seconds: under attack, three attacks. Below, every check shows what it found, what's clear, and what
> this capture can't show."

*Action:* on the **Issues** tab, read the first card's title and the first two fix steps. Open **Why we think so**.

> "Someone is pretending to be the router. We don't just say 'attack'. We show the evidence for both sides: it
> answers for the router's address without being asked, and it actually relays the laptop's traffic, so it's a man
> in the middle. Nothing points to a harmless fault, so it's an attack, critical severity."

*Action:* open **Evidence** on that card, then point at the Wireshark filter.

> "These are the exact packets, and here's a filter to check it yourself in Wireshark."

*Action:* click the **Incidents** tab.

> "And it connects the dots into one story: first the attacker scanned the router, then took over the laptop's
> traffic, then sent the laptop a fake address for the bank's website."

### 1:35 – 2:15 · Same symptom, different verdict (the core idea)

*Action:* **Faults** → `duplicate_ip.pcap`.

> "Here an address is again claimed by two devices: the same symptom. But both devices have their own normal
> traffic and they answer real questions. So it's a fault, two devices with the same IP, and the fix is a settings change."

*Action:* **Harmless** → `router_replacement.pcap`.

> "And when evidence is mixed, like a router that was just replaced, it honestly says 'uncertain' and tells you
> what to check first."

### 2:15 – 2:35 · A security risk most tools miss (Faults → `cleartext_logins.pcap`)

> "It also spots passwords sent without encryption, here over FTP and a router admin page. Notice it never shows
> the password and masks the username."

### 2:35 – 3:10 · Safety

*Action:* **Bad files** → `malicious_xss_dnsname.pcap`.

> "Captures can be hostile. These DNS names contain script code. They're shown as plain text and nothing runs."

*Action:* **Bad files** → `malformed_huge_record.pcap`.

> "This file claims a single packet is 4 gigabytes. It's read safely and stops cleanly with a warning."

*Action:* upload `samples/port_scan.pcap` (downloaded from GitHub), then open **Analysis log** under the verdict.

> "This log is what really happened to the uploaded file: its type checked by magic bytes, its SHA-256 fingerprint,
> parsed in a sandbox with memory and time limits, and, last line, the file deleted from the server."

*Action:* open the **Security & privacy** tab on any result.

> "Every result shows the file's SHA-256 fingerprint and how it was protected: sandboxed parsing with time and
> memory limits, the file deleted right after analysis, no internet connections, and a rate limit to keep the
> service up."

### 3:10 – 3:35 · Report and proof

*Action:* go back to `attack_chain.pcap`, toggle **Hide IPs**, click **⬇ HTML report**, open it, and scroll through the
summary, findings table and incident.

> "One click gives a shareable report, with addresses masked if you want."

*Action:* show the README evaluation table on GitHub (or run `python evaluate.py`).

> "On twenty labelled samples, including tricky harmless look-alikes, it finds all 24 issues with the right verdict
> and no false alarms. They're synthetic samples, and we say so."

### 3:35 – 3:45 · Close

> "CaughtIn4K tells you what's wrong with your network, whether it's an attack, and what to do about it."

---

**After recording:** upload to YouTube (Unlisted) or Google Drive ("anyone with the link"), check the link in a
private window, and send it to be added to the README. GitHub blocks files over 100 MB, so link it rather than
committing it.
