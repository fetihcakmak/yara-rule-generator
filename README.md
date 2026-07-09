<div align="center">
<pre>
██╗   ██╗ █████╗ ██████╗  █████╗ 
╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
 ╚████╔╝ ███████║██████╔╝███████║
  ╚██╔╝  ██╔══██║██╔══██╗██╔══██║
   ██║   ██║  ██║██║  ██║██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
 ██████╗ ███████╗███╗   ██╗
██╔════╝ ██╔════╝████╗  ██║
██║  ███╗█████╗  ██╔██╗ ██║
██║   ██║██╔══╝  ██║╚██╗██║
╚██████╔╝███████╗██║ ╚████║
 ╚═════╝ ╚══════╝╚═╝  ╚═══╝
</pre>
</div>

# 📝 YARA Rule Generator

> Verilen bir dosyayı (malware örneği, şüpheli binary) analiz ederek içindeki yüksek skorlu stringleri, API çağrılarını ve IOC'leri çıkarıp otomatik olarak geçerli bir YARA kuralı üreten araç.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![Stdlib](https://img.shields.io/badge/Dep-Stdlib_Only-success)](./)
[![Status](https://img.shields.io/badge/Status-Active-success)](./)

---

## 📈 Proje Hakkında

Bu araç, bir dosyadan ASCII/Wide stringleri çıkarır, bunları tehdit skorlarına göre sıralar ve en yüksek puanlı stringleri kullanarak otomatik bir YARA kuralı üretir.

**Commit Geçmişi:**
| Commit | Açıklama |
|--------|----------|
| `string extractor and hash calculator` | ASCII/Wide string çıkarma, MD5/SHA256 hash hesaplama, tehdit skorlama. |
| `yara rule builder and condition engine` | meta/strings/condition blokları üreten YARA şablon motoru. |
| `cli interface and rule export engine` | Argparse CLI, demo modu, dosya çıktısı ve renkli terminal. |

---

## 🧠 Mimari

```
main.py
  ├── generators/string_extractor.py  ← ASCII/Wide string çıkarma + tehdit skorlama
  ├── generators/hash_calculator.py   ← MD5/SHA1/SHA256 hesaplama
  └── generators/rule_builder.py      ← YARA kuralı meta/strings/condition üretici
```

---

## ⚡ Kullanım

```bash
# Demo modu (simüle edilmiş malware analizi)
python main.py --demo

# Gerçek dosya taraması
python main.py --scan malware.exe

# Kuralı dosyaya kaydet
python main.py --scan sample.bin --output rule.yar --top 20
```

---

*Fetih Çakmak — Cybersecurity Portfolio*
