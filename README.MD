


# 🛡️ SecOps-Research-Framework (SRF)

> **Otonom Savunma, Sürekli Doğrulama ve "Detection as Code" Mimarisi**

![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg)
![Language](https://img.shields.io/badge/language-Bash%20%7C%20Python-orange.svg)

## 📖 Proje Hakkında
**SecOps-Research-Framework (SRF)**, geleneksel siber güvenlik operasyonlarını (SOC) pasif bir izleme süreci olmaktan çıkarıp, kendi kendini test eden ve doğrulayan **otonom bir mühendislik disiplinine** dönüştürmeyi hedefler.

Yazılım dünyasındaki **CI/CD (Sürekli Entegrasyon/Dağıtım)** prensiplerini siber güvenliğe uyarlayan bu proje, sistemin tespit yeteneklerini sürekli olarak **"Watchdog" (Gözcü)** mekanizmasıyla denetler ve "Sessiz Hataları" (Silent Failures) ortadan kaldırır.

---

## 🚀 Temel Özellikler

### 1. Otonom Test (Auto-Test Ability)
Sistem, saldırganı beklemez. Periyodik olarak kendine zararsız, simüle edilmiş saldırı logları gönderir ve bunları tespit edip edemediğini kontrol eder.
* **Trigger:** Sahte saldırı simülasyonu.
* **Verify:** API üzerinden tespit doğrulaması.
* **Report:** Anlık [PASS] veya [FAIL] durumu.

### 2. Yönetim Konsolu (SRF-CLI)
Tüm framework, kullanıcı dostu bir **Komut Satırı Arayüzü (CLI)** üzerinden yönetilir.
* Sistem sağlık kontrolü.
* Tek tuşla otonom test başlatma.
* Denetim (Audit) loglarını görüntüleme.

### 3. Detection as Code
Güvenlik kuralları statik ayarlar değil, versiyonlanabilir yazılım kodları olarak yönetilir (`src/rules/local_rules.xml`).

---

## 🛠️ Mimari ve Bileşenler

Proje, endüstriyel standartlara uygun modüler bir dizin yapısına sahiptir:

```text
SecOps-Research-Framework/
├── project.json            # Proje Kimliği ve Metadata
├── src/
│   ├── srf-cli.sh          # Yönetim Aracı (Orkestrasyon)
│   ├── automation/         # Otonom Test Motoru (Watchdog)
│   └── rules/              # Tespit Kuralları (Logic Layer)
├── docs/                   # Mimari Şemalar ve Kullanım Kılavuzu
└── specs/                  # Sistem Gereksinimleri ve Analiz
