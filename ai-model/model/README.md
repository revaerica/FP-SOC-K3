# Model Artifacts

Folder ini adalah **output hasil training** (dibuat otomatis oleh `training/train_model.py`
atau notebook `training/SOC_training.ipynb` saat dieksekusi).

> ⚠️ **Sumber kebenaran model ada di `../training/`**, bukan di sini.
> Folder `model/` ini dulunya duplikat kosong yang menyesatkan dan sudah dibersihkan.

## Cara (re)generate artifact di sini

```bash
cd ai-model/training
python train_model.py        # menghasilkan model.pkl, scaler.pkl, feature_columns.json
```

Secara default script menulis ke folder `training/` itu sendiri. Untuk konsistensi,
`integration/config.yaml` selalu membaca dari `../training/`.

## File yang seharusnya ada setelah training

| File | Fungsi |
|------|--------|
| `model.pkl` | Random Forest terlatih (load via `joblib.load`) |
| `scaler.pkl` | StandardScaler (dipakai Logistic Regression; RF tidak butuh) |
| `feature_columns.json` | Urutan 6 fitur: `rule_id, rule_level, freq_per_minute, hour_of_day, src_port, dst_port` |
