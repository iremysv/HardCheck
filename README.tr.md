# HardCheck

Python 3.11+ ile geliştirilen, Linux yapılandırmalarını salt okunur inceleyen CLI.

## Mevcut durum

İlk altı aşama tamamlandı: toplam 18 SSH, yerel hesap, dosya sistemi, ağ, çekirdek
ve eski servis kontrolü; tarama motoru ve doğrulanan YAML politikaları. Dağıtım,
servis yöneticisi ve olası konteyner kapsamı sonuçlarda belirtilir. Kalite kontrolleri
GitHub Actions üzerinden Python 3.11/3.12 için elle başlatılabilir; commitler
otomatik çalıştırma tetiklemez.

Terminal özeti, JSON raporları ve şeffaf puanlama kullanılabilir.
HTML raporları ve Türkçe uygulama çıktıları sonraki aşamalardadır.
Henüz uygulanmayan seçenekler hata kodu 2 döndürür.

## Kurulum ve kullanım

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m hardcheck list-checks
python -m hardcheck scan
python -m hardcheck scan --explain
python -m hardcheck scan --config examples/policy.yaml --min-severity high
```

Normal kullanıcı hesabıyla çalıştırın. Dosya izinleri nedeniyle değerlendirilemeyen
ayarlar güvenli sayılmaz. WARN sonucunu kaldırmak amacıyla yetki yükseltmeyin.

| Kontrol | Beklenen ayar |
| --- | --- |
| SSH-001 | PermitRootLogin no |
| SSH-002 | PasswordAuthentication no |
| SSH-003 | MaxAuthTries: 1–4 |
| SSH-004 | PermitEmptyPasswords no |
| USR-001 | Yerel shadow kayıtlarında boş parola alanı yok |
| USR-002 | UID 0 yalnızca root hesabında |
| USR-003 | Yeni hesaplar için PASS_MAX_DAYS: 1–90 |
| USR-004 | Karakter kredileri sonrası yapılandırılmış uzunluk en az 12 |
| FS-001 | /etc/passwd: root sahipliği ve tam 0644 izinleri |
| FS-002 | /etc/shadow: root sahipliği ve 0640 izinlerinin alt kümesi |
| FS-003 | /tmp: root sahipliği, dizin türü ve sticky bit |
| FS-004 | Taranan /etc kapsamındaki normal dosyalarda herkese yazma izni yok |
| NET-001 | Desteklenen etkin giriş filtreleme kanıtı |
| NET-002 | IPv4/IPv6 TCP 21/23 portlarında dinleyici yok |
| NET-003 | IPv4 ve genel IPv6 yönlendirme kapalı |
| KRN-001 | Canlı randomize_va_space = 2 |
| KRN-002 | Canlı dmesg_restrict = 1 |
| SVC-001 | Bilinen telnet/rsh paketleri ve systemd birimleri yok |

PASS, çalışan SSH servisinin bu dosyayı kullandığını kanıtlamaz. Match blokları,
desteklenmeyen veya okunamayan yapılandırmalar WARN üretir. Teknik sınırlar ve
YAML şeması: [2. adım belgesi](docs/step-02.md). Hesap ve dosya sistemi
sınırları: [3. adım belgesi](docs/step-03.md). Ağ, servis ve ortam
sınırları: [4. adım belgesi](docs/step-04.md).

Çıkış kodları: 0, gösterilen FAIL ve dahili ERROR bulunmadığını; 1, gösterilen FAIL
bulunduğunu; 2, geçersiz/desteklenmeyen seçenek veya dahili hata olduğunu belirtir.
WARN/SKIP uygunluk kanıtı değildir. Önem filtresi gösterilen bulgulara ve FAIL
çıkışına uygulanır; dahili hata filtrelense de çıkış kodu 2 olur.

## Bulguyu açıklama

`scan --explain` beklenen değeri, güvenli gözlemleri, gerekçeyi, kaynağı ve elle
uygulanacak düzeltme rehberini gösterir. Kanıt alanlarında hesap adı, parola alanı,
özel dosya yolu veya ham komut çıktısı bulunmaz. Bilinmeyen ve kısmi değerlendirme
ayrıca belirtilir; hiçbir düzeltme otomatik uygulanmaz.
Teknik ayrıntılar: [bulgu ve kanıt modeli](docs/findings.md).

## Doğrulama

```sh
python -m ruff check .
python -m pytest --cov=hardcheck --cov-report=term-missing
```

Testler geçici dosyalar kullanır; sistem ayarlarını değiştirmez. Sanal ortamları,
anahtarları, kimlik bilgilerini ve yerel tarama verilerini repoya eklemeyin.
Proje geliştirme aşamasındadır; mevcut kontroller tam sistem güvenlik denetimi
yerine geçmez. Lisans: MIT.

## 6. aşama: raporlama ve puanlama

Terminal özeti, JSON raporu ve `--output` ile özel izinli yeni dosyaya kayıt
kullanılabilir. Puan yalnızca PASS ve FAIL üzerinden hesaplanır; WARN, SKIP
ve ERROR başarı sayılmaz. Kesin değerlendirilen kontrol oranı ayrıca gösterilir.
Filtre dışında kalan ERROR da çıkış kodu 2 üretir. HTML ve Türkçe çıktı
henüz desteklenmez. Ayrıntılar: [Reporting](docs/reporting.md).
