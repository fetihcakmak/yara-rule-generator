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

## ⚡ Kurulum

```bash
git clone https://github.com/fetihcakmak/yara-rule-generator.git
cd yara-rule-generator
python main.py --demo   # Ek bağımlılık gerekmez (yalnızca stdlib)
```

## 🚀 Kullanım

```bash
# Demo modu (simüle edilmiş malware analizi)
python main.py --demo

# Gerçek dosya taraması
python main.py --scan malware.exe

# Kuralı dosyaya kaydet
python main.py --scan sample.bin --output rule.yar --top 20
```

## 🖥️ Örnek Çıktı

```
rule demo_malware_sample
{
    meta:
        author = "fetihcakmak"
        description = "Auto-generated YARA rule (8 strings, threat: high)"
        threat_level = "high"
        md5 = "977e007a23e9c1a7be5394f0e7ee76b0"
        sha256 = "00749bb5d39fe0cc28f1381d15d99f43f4aa345600cc347d5ee826bc7d2452f2"

    strings:
        $s0 = "VirtualAllocEx"
        $s1 = "WriteProcessMemory"
        $s2 = "CreateRemoteThread"
        $s5 = "http://malicious-c2.evil.com/payload"

    condition:
        4 of ($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7)
}
```

## ⚠️ Etik Kullanım

Yalnızca sahip olduğunuz veya analiz için yetkilendirildiğiniz malware örnekleri üzerinde kullanın. Şüpheli dosyaları izole/sanal bir ortamda (VM, sandbox) tutun — bu araç dosyayı çalıştırmaz, yalnızca statik olarak stringlerini okur, ancak incelediğiniz örneğin kendisi zararlı olabilir.

## 📄 Lisans

Bu depo şu an bir lisans dosyası içermiyor. Kullanım koşulları için proje sahibiyle iletişime geçin.

---

*Fetih Çakmak — Cybersecurity Portfolio*
