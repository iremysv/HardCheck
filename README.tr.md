# HardCheck

Python 3.11+ ile geliştirilen, Linux yapılandırmalarını salt okunur inceleyen CLI.

## Mevcut durum

İlk üç aşama tamamlandı: toplam 12 SSH, yerel hesap ve dosya sistemi kontrolü;
kayıt sistemi, tarama motoru ve doğrulanan YAML politikaları. Kalite kontrolleri
GitHub Actions üzerinden Python 3.11/3.12 için elle başlatılabilir; commitler
otomatik çalıştırma tetiklemez.

JSON/HTML raporları, Türkçe uygulama çıktıları, puanlama ve NET/KRN/SVC kontrol aileleri
sonraki aşamalardadır. Henüz uygulanmayan seçenekler hata kodu 2 döndürür.

## Kurulum ve kullanım

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m hardcheck list-checks
python -m hardcheck scan
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

PASS, çalışan SSH servisinin bu dosyayı kullandığını kanıtlamaz. Match blokları,
desteklenmeyen veya okunamayan yapılandırmalar WARN üretir. Teknik sınırlar ve
YAML şeması: [2. gün belgesi](docs/day-02.md). Hesap ve dosya sistemi
sınırları: [3. gün belgesi](docs/day-03.md).

Çıkış kodları: 0, gösterilen FAIL ve dahili ERROR bulunmadığını; 1, gösterilen FAIL
bulunduğunu; 2, geçersiz/desteklenmeyen seçenek veya dahili hata olduğunu belirtir.
WARN/SKIP uygunluk kanıtı değildir. Önem filtresi gösterilen bulgulara ve FAIL
çıkışına uygulanır; dahili hata filtrelense de çıkış kodu 2 olur.

## Doğrulama

```sh
python -m ruff check .
python -m pytest --cov=hardcheck --cov-report=term-missing
```

Testler geçici dosyalar kullanır; sistem ayarlarını değiştirmez. Sanal ortamları,
anahtarları, kimlik bilgilerini ve yerel tarama verilerini repoya eklemeyin.
Proje geliştirme aşamasındadır; mevcut kontroller tam sistem güvenlik denetimi
yerine geçmez. Lisans: MIT.
