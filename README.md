# TürkDPI - Gelişmiş DPI Bypass Aracı

TürkDPI, Türkiye'deki internet servis sağlayıcılarının DPI (Deep Packet Inspection) engellemelerini aşmak için geliştirilmiş, kullanıcı dostu ve özelleştirilebilir bir araçtır.

## 🚀 Özellikler

- 🛡️ 9 farklı DPI bypass modu (Legacy ve Modern modlar)
- 🌐 Otomatik DNS yapılandırması ve DoH desteği
- 🔒 SSL/TLS güvenlik optimizasyonları
- ⚡ QUIC protokol kontrolü
- 🔄 Otomatik başlatma seçeneği
- ⚙️ Özelleştirilebilir ayar dosyası (settings.txt)
- 🎯 Türkiye'deki ISP'ler için özel optimizasyonlar

## 📋 Sistem Gereksinimleri

- Windows 10 veya Windows 11
- .NET 6.0 Runtime
- Yönetici hakları

## 💻 Kurulum

1. [Releases](../../releases) sayfasından en son sürümü indirin
2. İndirdiğiniz ZIP dosyasını açın
3. `TurkDPI.exe` dosyasını yönetici olarak çalıştırın

## 🔧 Kullanım

### Hızlı Başlangıç:

1. Programı yönetici olarak çalıştırın
2. Ana menüden "DPI Bypass'ı Etkinleştir (settings.txt'den)" seçeneğini seçin
3. Ayarların uygulanmasını bekleyin

### settings.txt ile Özelleştirme:

Program klasöründeki `settings.txt` dosyasını düzenleyerek tüm ayarları özelleştirebilirsiniz:

```ini
# DPI Bypass Modu (0-8)
DPI_MODE=8                # Varsayılan: Modern5 (Tam koruma)

# QUIC ve Pasif DPI Engelleme
BLOCK_QUIC=true          # QUIC protokolünü engelle
BLOCK_PASSIVE_DPI=true   # Pasif DPI engellemesini etkinleştir

# Fragmentasyon Değerleri
HTTP_FRAGMENTATION=2      # HTTP için (2-6 arası)
HTTPS_FRAGMENTATION=40    # HTTPS için (40-120 arası)

# DNS Ayarları
DNS_PROVIDER=1           # 1: Cloudflare, 2: Google, 3: OpenDNS, 4: Özel
DNS_PRIMARY=1.1.1.1      # Özel DNS için birincil sunucu
DNS_SECONDARY=1.0.0.1    # Özel DNS için ikincil sunucu
```

### DPI Bypass Modları:

1. **Legacy Modlar:**
   - Legacy1: En uyumlu mod (Türkiye için önerilen)
   - Legacy2: HTTPS için daha iyi hız
   - Legacy3: HTTP ve HTTPS için daha iyi hız
   - Legacy4: En iyi hız

2. **Modern Modlar:**
   - Modern1: Kararlı mod
   - Modern2: Hızlı mod
   - Modern3: Güvenli mod
   - Modern4: Ultra mod
   - Modern5: Tam koruma (Varsayılan)

## ⚠️ Önemli Notlar

- Program her zaman yönetici olarak çalıştırılmalıdır
- DPI bypass'ı devre dışı bıraktıktan sonra bilgisayarı yeniden başlatmanız önerilir
- Bazı antivirüs programları uygulamayı yanlışlıkla tehdit olarak algılayabilir
- Uygulama tamamen yasal ve güvenlidir, kaynak kodu açıktır

## 🆘 Sık Karşılaşılan Sorunlar

1. **Program Açılmıyor:**
   - Yönetici olarak çalıştırmayı deneyin
   - .NET 6.0 Runtime'ın yüklü olduğundan emin olun

2. **Bypass Çalışmıyor:**
   - settings.txt dosyasındaki ayarları kontrol edin
   - Farklı bir DPI modunu deneyin
   - DNS ayarlarını kontrol edin

3. **SSL Hatası:**
   - Tarayıcınızı tamamen kapatıp yeniden açın
   - Modern5 modunu kullanmayı deneyin

## 🔄 Güncelleme Geçmişi

### v1.0.0
- İlk kararlı sürüm
- settings.txt ile özelleştirilebilir ayarlar
- 9 farklı DPI bypass modu
- Otomatik DNS yapılandırması
- SSL/TLS optimizasyonları
- Otomatik başlatma desteği
- Gelişmiş hata yönetimi

## 👥 Katkıda Bulunma

1. Bu depoyu fork edin
2. Yeni bir branch oluşturun (`git checkout -b yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
4. Branch'inizi push edin (`git push origin yeni-ozellik`)
5. Pull Request oluşturun

## 📝 Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

## ⚡ Geliştirici Notu

Bu uygulama, internet özgürlüğünü desteklemek ve kullanıcıların yasal içeriklere erişimini kolaylaştırmak amacıyla geliştirilmiştir. Lütfen sorumlu kullanın. 