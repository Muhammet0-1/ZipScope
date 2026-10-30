# ZipScope 1.0.0

Son ZIP'in **dosya envanterini**, önceden hazırlanmış JSON izin listesiyle
karşılaştırır. Çevrimdışı çalışır; yalnız Python standart kütüphanesini kullanır.
İngilizce rehber: [README.md](README.md).

MIT lisanslıdır; LICENSE dosyasını oku. Sonuç 0 olduğunda söylenebilecek
şey **envanter listeyle uyumlu** ifadesidir. İçeriğin güvenliği kanıtlanmaz.

Kaynak: https://github.com/Muhammet0-1/ZipScope
İndirme: https://lordms.net/downloads/zipscope-1-0-0.zip

## Başlangıç

Python 3.10 veya üzeri gerekir. Ek paket kurulmaz. `arac` dizininden:

```console
python3 zipscope.py examples/demo-match.zip examples/allowlist.json
python3 zipscope.py examples/demo-findings.zip examples/allowlist.json
python3 zipscope.py examples/demo-findings.zip examples/allowlist.json --json
```

Windows'ta genellikle `python3` yerine `py -3` kullanılır; Windows ve macOS
denenmedi. Paket içindeki iki ZIP yalnız sentetik yer tutucular taşır. Hiçbir üye
çalıştırılmaz. Demoları yeniden üretmek için mevcut demo ZIP'lerini başka yere
aldıktan sonra `python3 examples/make_demo.py` komutunu açıkça çalıştırabilirsin.
Bu ayrı yardımcı iki sabit arşiv yazar, mevcut dosyaların üzerine yazmaz.
ZipScope CLI yalnız okur.

Bulgu demosunun çıktısı ve çıkış kodu 1:

```text
ZipScope: inventory differs from policy
missing: "LICENSE"
unexpected: "debug.log"
```

Önceden yazılan örnek izin listesi:

```json
{"version":1,"files":["README.md","LICENSE","tool.py"]}
```

Listeyi yayınlamayı amaçladığın dosyalardan oluşturup gözden geçir. İncelenen
ZIP'ten otomatik liste üretip onaylı sayan bir komut yoktur. Wildcard, klasör
izni, hariç tutma deseni ve otomatik düzeltme desteklenmez.

## Girdi ve karşılaştırma kuralları

İki konumsal argüman ZIP ve izin listesini açıkça seçer. Klasör taranmaz. Girdiler
yalnız okunur olarak açılır ve normal dosya olmalıdır. Linux'ta giriş symlink'i
ve özel dosyalar reddedilir. Başka işletim sistemlerinde `O_NOFOLLOW` bulunmayabilir;
bu platformlarda giriş symlink'i davranışı doğrulanmadı.

UTF-8 JSON tam olarak `version` (boolean değil, tamsayı 1) ve `files` alanlarını
taşımalıdır. `files`, 1–4096 benzersiz tam göreli dosya yoludur. Boş liste,
UTF-8 BOM, yinelenen JSON anahtarı, fazladan alan ve bozuk JSON hata verir.
Üst klasör adını da yaz: `release/tool.py` ile `tool.py` farklıdır. Boşluklar
kırpılmaz; ortak yol öneki kaldırılmaz.

Yollar büyük/küçük harfe duyarlı ve Unicode kod noktalarıyla birebir karşılaştırılır.
Unicode normalleştirme, harf küçültme ve slash dönüştürme yapılmaz. ZIP'in UTF-8
bayrağı varsa UTF-8, aksi durumda CP437 kullanılır. Görünüşü benzer adlar farklı
olabilir. Metin çıktısında adlar JSON dizgesi olarak tırnaklanır; tüm çıktılarda
ASCII kaçışları kullanılır. Terminal kontrol karakterleri etkisiz gösterilir.
Dosya adları da özel bilgi taşıyabilir; raporu paylaşmadan önce incele. Girdi
dosyasının sistem yolu, arşiv yorumları, gövdeler, zaman damgaları ve ham exception
mesajları çıktıya girmez.

`/` ile biten geçerli klasör girdileri doğrulanır ve sayılır, dosya karşılaştırmasına
katılmaz. Boş klasörler politikayla zorunlu tutulmaz. Açık klasör girdisi olmadan
`src/tool.py` kabul edilir. Yinelenen klasör girdisi ve dosya/klasör çakışması hata
verir. Sıkıştırılmamış boyutu sıfır olmayan klasör girdisi desteklenmez. Boş ZIP,
listedeki bütün dosyaları eksik raporlar.

| Kod | Anlam |
|---|---|
| 0 | Envanter listeyle uyumlu |
| 1 | Tamamlanan karşılaştırmada eksik ve/veya beklenmeyen dosya var |
| 2 | Argüman/girdi hatası, okunamayan, bozuk, desteklenmeyen veya sınırı aşan girdi; karşılaştırma tamamlanmadı |

`--help` ve `--version` karşılaştırma yapmadan 0 döndürür. JSON alanları:
`schema_version`, `status` (`match`, `findings`, `error`), sıralı `missing` ve
`unexpected` dizileri, `issues`, `counts`. Hata sonucu sabit bir issue kodu ve
gerekirse kaçışlanmış üye adı içerir; karşılaştırma dizileri ve sayaçlar boştur.
Aynı değişmeyen girdi/komut aynı çıktıyı üretir. Çalıştırma saati eklenmez.
Çıktı stdout'a yazılır; dosyaya yönlendirmeyi isteyen kişi kendi shell'inde yapar.
ZipScope shell çağırmaz ve çıktı dosyası oluşturmaz.

## Biçim ve kaynak sınırları

Tek diskli klasik ZIP merkez dizini desteklenir. ZIP64, şifreleme, tanınmayan
bayrak/sıkıştırma kimliği, kendini açan arşiv öneki, sondaki ek baytlar, belirsiz
son kayıt, alternatif Unicode-yol alanı ve Unix link tanımlayabilen bazı eski
ek alanlar reddedilir. Tanınan sıkıştırma kimlikleri 0, 8, 12 ve 14'tür;
hiçbir decompress işlemi yapılmaz. Bu kimliğin tanınması, sıkıştırılmış gövdenin
geçerli olduğunu göstermez.

Mutlak yol, iki nokta üst üste, ters slash, boş/`.`/`..` bileşeni, kontrol/format/
surrogate karakteri ve Unicode satır ayırıcıları hata verir. Bileşen sonundaki
nokta/boşluklar ve yaygın Windows aygıt adları (`NUL`, `CON` vb.) reddedilir.
Unix symlink/özel dosya metadata'sı desteklenmez; DOS üretici bayrağıyla sunulan
symlink mod bitleri de reddedilir. Bilinmeyen metadata kurallarıyla ifade edilen
her olası link yorumunu tespit etme garantisi yoktur.

Sabit üst sınırlar: ZIP 64 MiB, merkez dizin 4 MiB, izin listesi 1 MiB,
klasörler dahil toplam 4096 girdi, ad başına 1024 ham bayt ve çözümleme sonrası
1024 UTF-8 bayt. Sınır yükseltme seçeneği yoktur. Merkez dizin yüklenmeden
boyutu/adedi kontrol edilir. Beyan edilen açılmış dosya boyutuna göre bellek
ayrılmaz; dosyalar açılmaz. Sınırlar kaynak kullanımını azaltır; güvenlik kanıtı
veya performans garantisi değildir.

Yalnız sınırlı ham son bölüm ve merkez dizin okunur. Son kaydı bulma taraması
fiziksel olarak gövde baytlarıyla örtüşebilir; gövde içerikleri yorumlanmaz.
Yerel üye başlıkları, gövdeler, CRC, imza ve yerel/merkez tutarlılığı doğrulanmaz.
Bozuk bir gövde veya izinli addaki değiştirilmiş içerik 0 sonucu alabilir.
Çalışırken girdiyi değiştirme; temel değişiklik algılama atomik snapshot değildir.

## Diğer kontrollerle birlikte kullan

[Git archive](https://git-scm.com/docs/git-archive) ağaçtan arşiv üretir;
[export-ignore](https://git-scm.com/docs/gitattributes#_creating_an_archive) bu
üretimde dışarıda kalacak dosyaları belirler. [Gitleaks](https://github.com/gitleaks/gitleaks)
içerikte sır arar. ZipScope ortaya çıkan son ZIP'in envanterini karşılaştırır.
Antivirüs, sır tarayıcısı, CRC/bütünlük doğrulayıcı, çıkarma aracı veya yayın
kaynağının kanıtı değildir. İzinli dosyadaki parola kapsam dışındadır.
[Python zipfile belgesi](https://docs.python.org/3/library/zipfile.html), metadata,
üye okuma ve çıkarma işlemlerini ayrı API'lerle açıklar. Kaynak kontrolü: 30 Ekim 2026.

## Test ve yayın durumu

`python3 -m unittest discover -s tests -v` komutunu kullan. Testler yalnız sentetik
dosyalardır; `.env` adı taşıyan üye de sahtedir. Gerçek müşteri projesi, `.env`
veya kişisel yedek kullanılmaz. Araç ağ/shell çağırmaz. Test takımı geçici ZIP'ler
oluşturur; demo yardımcısı kendi sabit örneklerini ayrıca yazar.

Yayın sürümü Linux x86_64 / CPython 3.14.8 üzerinde doğrulandı: kaynakta 42/42,
son araç ZIP'inde 42/42 test geçti. Bağımsız inceleyici aynı test takımlarını ve
kaynak/paket runtime'larında toplam 36 CLI durumunu da doğruladı. Windows, macOS
ve diğer Python sürümleri denenmedi. Bu kontroller bağımsız güvenlik denetimi
veya bütün ZIP varyantlarının desteklendiğinin kanıtı değildir.

MIT lisansı: LICENSE dosyasını oku. Sentetik demo arşivlerindeki LICENSE girdisi
envanter örneğinin yer tutucusudur; gerçek dağıtım lisansı değildir.
