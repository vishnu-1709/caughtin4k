# CaughtIn4K demo video script (target 3:30, hard limit 5:00)

**Before recording:** open <https://caughtin4k.streamlit.app/> 5 minutes early and load one sample, because the free host
sleeps when idle. Use a 1280-wide browser window at 100% zoom. Close other tabs. Speak slowly; every line below is
about 10–15 seconds.

---

### 0:00 – 0:20 · The problem (show the home page)

> "When the network breaks in a small office or a college lab, nobody there can read a packet capture. And the
> worst part: a harmless fault and an attack look exactly the same to a user. Both just feel like 'the internet is
> broken'. CaughtIn4K fixes that."

*Point at:* the tagline and the privacy line ("analysed and deleted immediately").

### 0:20 – 0:40 · What it does (still on home)

> "You upload a capture from Wireshark. CaughtIn4K runs ten checks: four kinds of attack, six kinds of fault.
> All the detection logic is our own; Scapy is only used to read the packets."

*Point at:* the "What CaughtIn4K checks" block.

### 0:40 – 1:30 · The mixed sample: answer first

*Action:* "Or try a sample" → `mixed_attack_and_fault.pcap`.

> "This capture has an attack and two faults mixed together. In three seconds the banner says: under attack, one
> attack, two faults, and where to start. Below it, every check shows its result."

*Action:* scroll to the first card.

> "Someone is pretending to be the router. The Raspberry Pi keeps telling the laptop 'I am the router', so the
> laptop's traffic goes through it. That's a man-in-the-middle. And here is exactly what to do, step by step."

*Action:* open **Why we think so**.

> "We don't just say 'attack'. We show the evidence for both sides: the router's address is involved, 87 replies
> nobody asked for, the same device also uses its own address. Nothing points to a harmless fault, so the score is
> 10 to 0: attack, high confidence."

*Action:* open **Evidence**, then point at the Wireshark filter.

> "Here are the exact packets, and a filter you can paste into Wireshark to check it yourself."

*Point at:* the 🔗 link line.

> "And it connects cause and effect: this spoofing is also why the laptop is losing packets. That's the second
> card. The third card, the NAS being down, is a separate, plain fault."

### 1:30 – 2:15 · Same symptom, different verdict (the core idea)

*Action:* select `duplicate_ip.pcap`.

> "Here's the hard part of the challenge. In this capture, an address is again claimed by two devices, which is
> the same symptom as before. But the replies answer real questions, both devices send their own normal traffic,
> and it's sporadic. So it's judged a fault: two devices were given the same IP. The fix is a settings change,
> not a security response."

*Action:* select `router_replacement.pcap`.

> "And when the evidence is mixed, for example the router was replaced, we say 'uncertain' honestly, and the advice
> starts with checks, not with unplugging things."

### 2:15 – 2:45 · Another attack chain (optional if time)

*Action:* select `rogue_dhcp_dns_hijack.pcap`.

> "A fake DHCP server makes itself the DNS server, then sends github.com to its own address. CaughtIn4K links
> them: the rogue DHCP *caused* the DNS hijack."

### 2:45 – 3:15 · Safety

*Action:* select `malicious_xss_dnsname.pcap`.

> "Captures can be hostile. This one has DNS names containing script code. They're shown as plain text and
> nothing runs."

*Action:* select `not_a_pcap.pcap` (or upload any non-capture file).

> "Wrong or broken files get a friendly message, never a crash. Uploads are analysed in a sandboxed process with
> size, time and memory limits and deleted immediately, and 'Hide IPs' masks every address, even in the reports."

*Action:* go back to the mixed sample, toggle **Hide IPs**, click **HTML report**, open it briefly.

### 3:15 – 3:40 · Proof and close

*Action:* show the README evaluation table on GitHub (or run `python evaluate.py` in a terminal).

> "On 17 labelled samples, including tricky harmless look-alikes, it finds all 19 issues with the right verdict
> and no false alarms. They're synthetic samples, so we say so in the README. It also runs locally and as a
> command-line tool."

> "CaughtIn4K: it tells you what's wrong with your network, whether it's an attack, and what to do about it."

---

**Checklist after recording:** upload to YouTube (Unlisted) or Google Drive (anyone with the link can view) and
check the link in a private window. Paste the link into the README (`Demo video:` line at the top) and into the
submission form. GitHub blocks files over 100 MB, so link it rather than committing it.
