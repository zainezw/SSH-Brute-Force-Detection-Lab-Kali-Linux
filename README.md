# SSH Brute-Force Detection Lab — Kali Linux

**Author:** Zaine
**Environment:** Kali Linux VM (self-contained — attacker and target on one host)
**Date:** October 5, 2026

---

## 1. Objective & Scope

This lab is the defensive counterpart to offline password cracking: instead of breaking hashes, it detects a live password-guessing attack from the logs it leaves behind. Working entirely within one Kali VM, I simulated a failed-login brute-force against the host's own SSH service, then hunted the activity the way a SOC analyst would — confirming the logs captured it, breaking the failures down by source and target, and writing a simple threshold-based alert rule. No system other than my own was involved.

**Tools used (all built into Kali):** `openssh-server`, `systemctl`, `journalctl`, `grep`, `sort`, `uniq`, and a short `bash` detection script.

---

## 2. Setup

Started the SSH service so there is something to attack and something to log the attempts:

```bash
mkdir ~/detection-lab && cd ~/detection-lab
sudo systemctl start ssh
sudo systemctl status ssh      # confirmed: active (running), listening on port 22
```

---

## 3. Simulating the Attack

Generated failed logins by attempting SSH as accounts that don't exist, using wrong passwords (three password attempts per connection):

```bash
ssh fakeuser@localhost
ssh admin@localhost
ssh root@localhost
```

Each attempt ended in `Permission denied`, producing a cluster of failed-login events — the same pattern a real brute-force leaves.

![SSH service started, failed login attempts, and log hunting](1.PNG)

---

## 4. Confirming the Logs

The classic `/var/log/auth.log` file was absent (modern Kali logs SSH to the systemd journal instead), so I pulled the events from the journal:

```bash
sudo journalctl -u ssh | grep "Failed password"
```

This returned the individual failure events, each timestamped and showing the targeted user and source.

---

## 5. Hunting — Turning Logs into Findings

Total failed attempts:

```bash
sudo journalctl -u ssh | grep -c "Failed password"
# 9
```

Failures grouped by targeted username:

```bash
sudo journalctl -u ssh | grep "Failed password" | grep -oP 'for (invalid user )?\K\w+' | sort | uniq -c | sort -rn
#   3 root
#   3 fakeuser
#   3 admin
```

**Findings:**
- **9 failed logins** in a short window — a clear spike, not normal user error.
- Attempts spread across `root`, `admin`, and `fakeuser` — targeting common high-value accounts is a brute-force signature.
- All attempts originated from a **single source** (`::1`, localhost over IPv6). One source hammering multiple accounts is textbook credential-guessing behavior.

> Note: the source here was IPv6 loopback (`::1`), so an IPv4-only extraction (`[0-9.]+`) returns nothing — a good reminder that detection logic has to account for both address families.

---

## 6. Detection Rule

Wrote a small script that counts failures and raises an alert when they cross a threshold — the core concept behind a SIEM correlation rule:

```bash
#!/bin/bash
THRESHOLD=5
COUNT=$(sudo journalctl -u ssh | grep -c "Failed password")
echo "Failed login attempts found: $COUNT"
if [ "$COUNT" -ge "$THRESHOLD" ]; then
  echo "[ALERT] Possible brute-force attack - $COUNT failures (threshold $THRESHOLD)"
else
  echo "[OK] Below alert threshold."
fi
```

Run:

```bash
chmod +x detect.sh
./detect.sh
# Failed login attempts found: 9
# [ALERT] Possible brute-force attack - 9 failures (threshold 5)
```

With 9 failures against a threshold of 5, the rule correctly fired `[ALERT]`.

![Detection script and the ALERT firing on 9 failures](2.PNG)

---

## 7. MITRE ATT&CK Mapping

| Technique ID | Name | Where it appears in this lab |
|--------------|------|------------------------------|
| T1110 | Brute Force | The overall attack pattern |
| T1110.001 | Password Guessing | Repeated wrong-password SSH attempts |
| T1078 | Valid Accounts | Targeting of `root` / `admin` accounts |

---

## 8. Defender Analysis — Why This Matters

**1. Rate and pattern, not single events.** One failed login is noise; nine across several privileged accounts from one source in minutes is an attack. Detection is about thresholds and clustering, which is exactly what the script models.

**2. The Windows parallel.** A Linux `Failed password` event is the direct equivalent of **Windows Event ID 4625** (failed logon); a lockout would be **Event ID 4740**. Watching these is the foundation of brute-force detection on any platform.

**3. Response and hardening.** The practical fixes:
- **fail2ban** — automatically bans an IP after N failures
- **Key-based SSH auth** — disable password login entirely
- **Account lockout policies** and rate limiting
- Forwarding these events to a SIEM for correlation and alerting

---

## 9. Conclusion

This lab completed the "attack then detection" picture: having cracked password hashes offline in a separate project, here I detected the live-guessing version of the same threat from its log trail. The workflow — simulate, confirm, hunt, alert — mirrors day-one SOC analyst work, and the threshold script demonstrates the logic behind automated detection. Paired with the password-cracking lab, it shows both sides of the credential-attack lifecycle.
