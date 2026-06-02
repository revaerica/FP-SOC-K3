# Setup TheHive — Manajemen Insiden

> **Catatan:** Integrasi TheHive dilakukan oleh kelompok referensi (SOC-C-K4).
> Fase ini (Kelompok 7 ITS) berfokus pada web server, DDoS, malware, dan SOAR
> menggunakan Active Response bawaan Wazuh.
>
> File ini disertakan untuk menjaga konsistensi struktur repo.

---

## Tentang TheHive

TheHive adalah platform manajemen insiden open-source yang dapat menerima alert
dari Wazuh secara otomatis. Setiap alert yang terpicu di Wazuh diteruskan sebagai
"Alert" di TheHive, yang kemudian bisa diproses menjadi "Case" oleh analis SOC.

---

## Integrasi Wazuh → TheHive (Referensi)

Jika ingin mengintegrasikan TheHive di lab ini, langkah umumnya:

### 1. Install TheHive via Docker di Manager

```bash
docker run -d \
  --name thehive \
  -p 9000:9000 \
  strangebee/thehive:latest
```

### 2. Konfigurasi integrasi di Manager

Tambahkan ke `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-w2thive</name>
  <hook_url>http://localhost:9000</hook_url>
  <api_key>YOUR_THEHIVE_API_KEY</api_key>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

### 3. Restart Manager

```bash
sudo systemctl restart wazuh-manager
```

---

## Status di Lab Ini

Untuk lab Kelompok 7 ITS (Shinta, Angga, Zaenal), SOAR diimplementasikan menggunakan **Active Response**
bawaan Wazuh (tanpa TheHive) karena:

- Lebih simpel untuk satu orang
- Active Response sudah cukup untuk membuktikan konsep SOAR
- Tidak membutuhkan container Docker tambahan di VM

Jika ingin memperluas ke TheHive, lihat repo referensi:
[syifanalfiah/SOC-C-K4](https://github.com/syifanalfiah/SOC-C-K4)
