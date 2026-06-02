# Folder Documentation

Folder ini berisi screenshot-screenshot bukti implementasi.

## Cara upload screenshot ke GitHub

1. Buka repo di browser GitHub
2. Masuk ke folder `Documentation/`
3. Klik **Add file → Upload files**
4. Drag & drop screenshot, lalu commit

## Daftar screenshot yang wajib ada

| Nama File | Isi | Checklist |
|-----------|-----|-----------|
| `webserver-active.png` | `systemctl status wazuh-webserver` — active (running) | ☐ |
| `webserver-browser.png` | Halaman `http://70.153.151.52` di browser | ☐ |
| `logtest-100200.png` | `wazuh-logtest` output rule 100200 match | ☐ |
| `logtest-100301.png` | `wazuh-logtest` output rule 100301 match + group rootcheck | ☐ |
| `alert-rekap.png` | Output `grep -c` rekap jumlah alert per rule | ☐ |
| `threat-hunting-syn.png` | Threat Hunting `rule.id:100200` — spike SYN flood | ☐ |
| `threat-hunting-http.png` | Threat Hunting `rule.id:100402` — 480 HTTP flood alerts | ☐ |
| `malware-detection.png` | Modul **Malware Detection** — EICAR alert wazuh-agent-1 | ☐ |
| `alert-detail.png` | Detail satu alert (rule.id, description, agent.name) | ☐ |
| `soar-quarantine.png` | `active-responses.log` baris KARANTINA | ☐ |
| `soar-quarantine-dir.png` | `ls -l /var/ossec/quarantine/` — file terkarantina | ☐ |
| `soar-dashboard.png` | Threat Hunting search `remove-malware` di Dashboard | ☐ |
| `soar-firewall-drop.png` | `active-responses.log` — add & delete firewall-drop | ☐ |

---

*Simpan screenshot langsung dengan nama file sesuai tabel agar link di README.md otomatis terhubung.*
