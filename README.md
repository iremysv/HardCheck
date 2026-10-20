# HardCheck

HardCheck, Linux güvenlik yapılandırmalarını salt okunur kontrollerle inceleyen ve bulguları yerel tarayıcı panelinde gösteren bir Python uygulamasıdır.

<!-- Add the cropped real Linux demo here only after the recording is supplied and verified. -->

## Amaç ve kontrol alanları

HardCheck, yapılandırma risklerini kanıtları ve elle uygulanabilecek önerilerle
görünür kılar. Sistem ayarlarını değiştirmez ve bulguları otomatik düzeltmez.
Mevcut Python kontrol motorunda **18 kontrol** bulunur:

- **SSH:** root oturumu, parola ile giriş, kimlik doğrulama deneme sınırı ve boş parola ayarları (`SSH-001`–`SSH-004`).
- **Yerel hesaplar ve parola politikası:** boş parola alanları, UID 0 hesapları, parola yaş sınırı ve yapılandırılmış parola uzunluğu (`USR-001`–`USR-004`).
- **Dosya sistemi:** `/etc/passwd`, `/etc/shadow` ve `/tmp` izinleri; taranan `/etc` kapsamındaki herkese yazılabilir normal dosyalar (`FS-001`–`FS-004`).
- **Ağ:** güvenlik duvarı kanıtları, TCP 21/23 dinleyicileri ve IPv4/IPv6 yönlendirme ayarları (`NET-001`–`NET-003`).
- **Çekirdek:** canlı ASLR ve `dmesg` erişim kısıtlaması ayarları (`KRN-001`, `KRN-002`).
- **Eski servisler:** bilinen telnet/rsh paketleri ve servis birimleri (`SVC-001`).

Kontrollerin ayrıntıları ve sınırları mevcut step belgelerinde yer alır:
[SSH ve yapılandırma](docs/step-02.md),
[hesaplar ve dosya sistemi](docs/step-03.md),
[ağ, çekirdek ve servisler](docs/step-04.md).

## Ubuntu’da ilk kurulum

Python 3.11 veya üzeri, Git ve `python3-venv` gereklidir. Proje kaynaklarının
`~/HardCheck` altında bulunduğu varsayılır. Normal kullanıcı hesabıyla çalıştırın:

```sh
cd ~/HardCheck
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/hardcheck install-launcher
```

`.venv` zaten varsa oluşturma adımını atlayın. Bu işlem Ubuntu uygulama menüsüne
**HardCheck** başlatıcısını ekler; sistem genelinde servis veya otomatik oturum
açılışı görevi kurmaz. İlk kurulumdan sonra günlük kullanım terminal gerektirmez.

Uygulama menüsünden **HardCheck**’e tıklayın. Başlatıcı yerel servisi açar ve
varsayılan tarayıcıda `http://127.0.0.1:8765/` adresini gösterir. Yeniden
başlatıldığında mevcut HardCheck oturumu doğrulanıp açılır. Port başka bir
uygulamadaysa hata gösterilir; bilinmeyen süreçler sonlandırılmaz.

Başlatıcı `.venv` içindeki Python yolunu kaydeder; proje taşınırsa başlatıcıyı
yeni ortamdan yeniden kurun. Tarayıcıyı kapatmak servisi durdurmaz. Çalışan bir
sürümü güncellediyseniz yeni kodu kullanmak için oturumu kapatıp yeniden açın.
Ayrıntılar: [yerel uygulama kurulumu ve yaşam döngüsü](docs/local-application.md).

## Taramayı başlat → bulguları incele → JSON/HTML indir

1. **Gerçek taramayı başlat** düğmesine basın. Mevcut Python kontrol motoru çalışır;
   panel hazır, çalışıyor, tamamlandı veya hata durumunu gösterir. Tarama sürerken
   ikinci tarama engellenir.
2. Sonuçlar otomatik gelir; dosya taşımanız gerekmez. Durum, önem ve kontrol alanı
   filtreleriyle bulguları daraltın veya arama yapın. Bir bulguyu açarak beklenen
   koşulu, **Gözlem / kanıt** alanını, gerekçeyi ve önerilen adımı inceleyin.
3. **Son tarama · JSON indir** ve **Son tarama · HTML indir** düğmeleri aynı
   tamamlanmış taramanın raporlarını indirir; yeniden tarama başlatmaz. HTML raporu
   çevrimdışı açılabilir.
4. Yeniden tarayabilir ve aynı sekmede açılmış raporları karşılaştırabilirsiniz.
   Yeni veya başarısız denemede önceki sonuç yeni başarılı sonuç gibi sunulmaz;
   önceki tarama etiketi gösterilir ve yerel indirme düğmeleri kapatılır.

**Rapor yükle** ile mevcut JSON raporlarını açma ve **Örnek tarama** ile temsili
verileri inceleme korunur. Yerel uygulamada örnek taramaya **Nasıl çalışır?**
bölümünden ulaşılır. Örnek tarama gerçek cihaz taraması değildir.
**Görüntülenen raporu JSON indir**, filtrelenmiş görünümü değil, o anda görüntülenen raporun
tamamını JSON olarak dışa aktarır; bu rapor elle yüklenmiş veya örnek olabilir.

Rapor geçmişi tarayıcı sekmesinin belleğindedir; kalıcı arşiv değildir. Servis
son tamamlanmış sonucu bellekte tutar. Yenileme bu sonucu geri getirebilir;
sekmenin eski karşılaştırma geçmişini getirmez. İçe aktarılan dosyalar sunucuya
gönderilmeden tarayıcıda işlenir. Ayrı [statik panel](web/README.md) de kullanılabilir;
statik panel tek başına gerçek tarama çalıştırmaz.

## Sonuçlar ve puanın sınırları

- **PASS:** Kontrol, değerlendirilebilen kapsam içinde beklenen koşulu sağlıyor.
- **FAIL:** Kontrol, beklenen koşula aykırı bir bulgu doğruladı.
- **WARN:** Değerlendirme belirsiz veya kısmi; elle inceleme gerekiyor.
- **SKIP:** Kontrol atlandı veya mevcut ortamda değerlendirilemedi.
- **ERROR:** Kontrol tamamlanamadı; bu sonuç uygunluk kanıtı değildir.

Özet bölümünde beş durumun sayıları ayrı gösterilir. Puanın yanında kesin
değerlendirilen kontrol sayısı ve kapsam yüzdesi yer alır.

Uyumluluk puanı **`100 × PASS / (PASS + FAIL)`** olarak hesaplanır. Yalnızca
gösterilen kesin değerlendirmeler puana girer; **WARN, SKIP ve ERROR başarı
sayılmaz**. PASS/FAIL yoksa puan verilmez. Kesin değerlendirilen kontrol oranı
ayrıca gösterilir. `%100`, sistemin bütünüyle güvenli olduğunu veya tüm kontrollerin
tamamlandığını göstermez. Filtrelenmiş raporların kapsamı da sınırlıdır.

Bilinmeyen kanıtlar bilinmeyen olarak kalır. Statik bir ayarın PASS olması,
çalışan servisin o yapılandırmayı kullandığını kanıtlamaz. Karşılaştırmada yalnızca
FAIL → PASS geçişi düzelmiş sayılır; eksik veya belirsiz sonuçlar düzeltme kanıtı
olarak sunulmaz. [Raporlama ve puanlama](docs/reporting.md) ile
[bulgu ve kanıt modeli](docs/findings.md) daha ayrıntılı açıklanmıştır.

## CLI ve kaldırma

Mevcut CLI kullanılmaya devam eder. Aşağıdaki komutlar etkinleştirilmiş sanal
ortam içindir; gerçek taramaları Linux üzerinde çalıştırın:

```sh
. .venv/bin/activate
python -m hardcheck --version
python -m hardcheck list-checks
python -m hardcheck scan --lang tr --explain
python -m hardcheck scan --format json --lang tr
mkdir -p scan-output
python -m hardcheck scan --format html --lang tr --output scan-output/report-tr.html
python -m hardcheck scan --config examples/policy.yaml --min-severity high
```

Rapor dili `--lang en|tr` ile seçilir. `--output` yeni dosya oluşturur; mevcut
bir dosyanın üzerine yazmaz. CLI çıkış kodu `0`, gösterilen FAIL ve dahili ERROR
olmadığını; `1`, gösterilen FAIL bulunduğunu; `2`, geçersiz girdi veya işlem
hatasını belirtir. Dahili ERROR filtrelense de çıkış kodu `2` olur. WARN/SKIP
bulunması tek başına başarısız çıkış kodu üretmez.

Başlatıcıyı ve paketi kaldırmak için, çalışan servisi oturumu kapatarak durdurduktan
sonra:

```sh
cd ~/HardCheck
.venv/bin/hardcheck uninstall-launcher
.venv/bin/python -m pip uninstall hardcheck
```

İndirilmiş raporlar otomatik silinmez.

## Test ve geliştirme

Proje kökünde sanal ortamı etkinleştirin. Panel testleri için Node.js de gereklidir:

```sh
. .venv/bin/activate
python -m pip install --upgrade 'pip>=26.2,<27'
python -m pip install -e '.[dev,security]'
python -m ruff check .
python -m pytest --cov=hardcheck --cov-report=term-missing
HARDCHECK_TEST_PYTHON=python node --test web/tests/report.test.cjs
python -m bandit -c pyproject.toml -r src scripts
python scripts/check_secrets.py
python scripts/audit_dependencies.py
```

Sır taraması Git index’indeki commit’e hazırlanmış içerikleri inceler;
stage edilmemiş değişiklikleri taramaz. Bağımlılık denetimi kurulu sürümleri
inceler ve ağ erişimi gerektirir; bağlantı hatası temiz sonuç sayılmaz.
GitHub Actions kontrolleri elle başlatılır; commit otomatik CI tetiklemez.

Python testleri sentetik girdilerle motoru, CLI’yi, yerel HTTP API’sini ve
paketlemeyi sınar. Node testleri DOM taklidi kullanır; gerçek tarayıcı testi değildir.
İsteğe bağlı gerçek Chromium testi için geliştirme ortamına `playwright` kurup
`--browser` ile kurulu Chromium yürütülebilir dosyasını belirtin:

```sh
PYTHONPATH=src .venv/bin/python scripts/validate_local_browser.py \
  --browser /path/to/chromium --output artifacts/local-browser
```

Bu test de sentetik tarama kullanır. Temiz wheel kurulumunu
`scripts/validate_install.py` ve `scripts/validate_local_install.py` doğrular.
Çalıştırma koşulları ve önceki sonuçlar [yerel uygulama doğrulama kaydındadır](docs/local-application.md).
Bu kayıt macOS testlerini gerçek Ubuntu/Firefox kabul testi olarak sunmaz;
güncel Linux başlatıcı → tarama → indirme akışının doğrulaması ayrıca yapılmalıdır.

## Güvenlik kapsamı ve sınırlamalar

- Tarama normal kullanıcıyla ve salt okunur çalışır. Otomatik sudo/root yükseltmesi
  veya düzeltme yapılmaz. Erişilemeyen ayarlar güvenli sayılmaz.
- Yerel servis yalnızca `127.0.0.1` üzerinde dinler. Tam Host/Origin doğrulaması,
  oturum çerezi, CSRF koruması ve kullanıcıya özel işletim sistemi kilidi vardır.
  Token URL’ye veya istek loglarına yazılmaz. API keyfî komut, Python kodu veya
  kullanıcı seçimi dosya yolu çalıştırmaz.
- Yerel raporlar dış sunucuya gönderilmez. Kamuya açık rapor sözleşmesi ham komut
  çıktısı veya parola özetleri yerine sınırlı, yapılandırılmış kanıt kullanır.
  Yine de raporlar cihazın yapılandırmasını anlatır; kişisel veri olarak saklayın.
- Koruma sınırı kötü niyetli web sayfaları ve çapraz origin istekleridir.
  Bilgisayarda çalışan kötü niyetli yerel yazılımlara karşı yalıtım sağlanmaz.
  Servisi internete açmayın veya port yönlendirmesiyle paylaşmayın.
- Gerçek tarama yalnızca Linux’ta desteklenir. macOS’ta yerel panel kullanılabilir,
  ancak gerçek tarama düğmesi kapalıdır. Konteyner/ağ ad alanı, dağıtım, izinler ve
  servis yöneticisi gözlemlerin kapsamını sınırlar; ana makine kapsamı doğrulanmaz.
- HardCheck tam sistem güvenlik denetimi veya güvenlik sertifikası değildir.
  Mevcut kontroller dışında kalan riskler ve çalışan servislerin etkin davranışı
  için ayrıca inceleme gerekir.

Sanal ortamları, `.env` dosyalarını, kimlik bilgilerini ve kişisel raporları Git’e
eklemeyin. Raporlar için dış bir klasör veya yok sayılan `scan-output/` kullanılabilir.

Ek belgeler: [tehdit modeli](docs/threat-model.md),
[güvenlik politikası](docs/SECURITY.md), [8. adım](docs/step-08.md),
[katkı rehberi](docs/CONTRIBUTING.md), [10. adım doğrulaması](docs/final-validation.md),
[sürüm özeti](docs/release-0.1.0.md) ve [yayın hazırlığı](docs/RELEASING.md).

Lisans: [MIT](LICENSE).
