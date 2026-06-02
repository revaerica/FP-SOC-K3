# Arsitektur Lab — Kelompok 7 ITS

## Infrastruktur

| Peran | VM | IP Public | IP Private | Fungsi |
|-------|----|-----------|------------|--------|
| Manager | wazuh-manager | 70.153.86.7 | 10.0.0.4 | Decoder + Rules + SOAR |
| Target | wazuh-agent-1 | 70.153.151.52 | 10.0.0.5 | Web Server + ClamAV |
| Attacker | wazuh-agent-2 | 48.193.46.1 | 10.0.0.6 | Sumber serangan |

- **Dashboard:** https://70.153.86.7 (admin / admin)
- **Website target:** http://70.153.151.52
- **SSH key:** wazuh-manager-key.pem
- **Platform:** Microsoft Azure (Virtual Network, NSG)

---

## Alur Data

```
[wazuh-agent-2 / Attacker]
      10.0.0.6
         │
         │  hping3 SYN/UDP/ICMP flood
         │  ddos_attack.sh HTTP flood
         ▼
[wazuh-agent-1 / Target]          [wazuh-agent-1 / Target]
      10.0.0.5                          10.0.0.5
  Web Server :80             +       malware_sim.sh
  iptables LOG               +       clamscan → clamav.log
  kern.log (SYN/UDP/ICMP)
  access.log (HTTP)
         │                                   │
         └──────────── Wazuh Agent ──────────┘
                     (log forwarding)
                            │
                            ▼
                  [wazuh-manager 10.0.0.4]
                  local_decoder.xml (kosong)
                  local_rules.xml (custom)
                  100200/201/202 → DDoS
                  100300/301/302 → Malware
                  100400/402     → HTTP Flood
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
         SIEM Alert                 SOAR Response
      Wazuh Dashboard           Active Response Engine
    Threat Hunting                      │
    Malware Detection       ┌───────────┴───────────┐
                        firewall-drop         remove-malware.py
                     (rule 100402)          (rule 100300/100301)
                     blokir IP 120s         karantina file malware
```

---

## Dependensi Antar Fase

```
Kelompok sebelumnya (prasyarat)
  └── Wazuh Manager + Indexer + Dashboard + Agent-1 + Agent-2 aktif
        └── Fase A: Deploy Web Server (Agent-1)
              └── Fase B: Konfigurasi Logging (iptables + ClamAV + ossec.conf)
                    └── Fase C: Custom Rules & Decoder (Manager)
                          └── Fase D: Eksekusi Serangan (Agent-2 → Agent-1)
                                └── Fase E: Verifikasi Deteksi (Dashboard)
                                      └── Fase F: SOAR (Manager + Agent-1)
```

> **Catatan:** Setiap fase bergantung pada fase sebelumnya. Jangan skip urutan,
> terutama Fase C (rules) harus ada sebelum Fase D (serangan) agar alert terpicu.

---

## Tim Kelompok 7

| Nama | NRP |
|------|-----|
| Shinta Alya Ramadani | 5027241016 |
| Angga Firmansyah | 5027241062 |
| Zaenal Mustofa | 5027241018 |
