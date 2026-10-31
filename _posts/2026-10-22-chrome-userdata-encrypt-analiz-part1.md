---
layout: post
title: "Google Chrome Windows, User Data Encryption Analizi Part1"
date: 2026-10-24
---

# Köken ve Tarih
Google Chrome, Chromium isimli açık kaynaklı tarayıcı projesinin ticari ve tescilli ek özelliklerle modifiye edilmiş bir versiyonudur. Chromium projesininde temel olarak Google tarafından geliştirilmeye başlandığı ve geliştirilmeye devam ettirildiğini bilmekte fayda var. Adamlar temelimiz bu, ürünümüz ise şu demişler yani.  

Biz bu yazıda bu devasa projenin User Data koruma refleks ve mekanizmasının derinlerine inicez. İlk Olarak User Data derken neyi kast ediyoruz bunu açıklayalım. 
Chromium, kullanıcıların tarayıcıyı kullanırken isteyerek yada istemeyerek bıraktığı çoğu kişisel veriyi kullanıcı deneyimini arttırmak için saklar. Öteki türlü her açıldığında sizin kim olduğunuzu bile bilmeyen bir tarayıcı ile uğraşır olurdunuz. Ne tarz şeyler saklar peki? Hemen hemen her şeyi:  
* Cookies - oturum/kimlik cookie’leri (SQLite). Şifreli (v10/v20).
* Login Data - kaydedilmiş kullanıcı adı/parolalar (SQLite). Şifreli.
* Web Data - autofill (form bilgileri) ve kredi kartı verileri (SQLite). Kart verisi şifreli.
* History - gezinme geçmişi, indirmeler (SQLite, şifresiz).
* Bookmarks - yer imleri (JSON, şifresiz).
* Preferences - profil ayarları (JSON, şifresiz).
* Local State Genel tarayıcı ayarları, v10 ve v20 anahtarları şifreli olarak burda tutuluyor (JSON, şifresiz).  

Ve daha başka bir sürü ıvır zıvır, her birinin yanında şifreli ve şifresiz ibaresini görüyorsunuz bu şuan güncel 159.0.8129.1 github tagında ki durum. Ben yazıyı yazdıktan sonra daha neler eklenir çıkarılır bilmem. Şifreli demek o dosyalardaki verilerin şifreli olarak tutulduğu anlamına geliyor ki bu yazıda ilgileneceğimiz konu tam olarak bu.  

Şimdi, elimizde ne olduğuna bakalım:  
- Yıl 2008, Chromium halka arz edilmiş, ondan fırlayan Google Chrome un beta sürümü Windows için yayınlandı. Bu sürümde User Data daki şifreli veriler Windows'un CryptProtectData/CryptUnprotectData çifti ile şifreleniyor ve deşifreleniyordu.
- Yıl 2019, Will Harris in issue ve ardından gelen commit i ile AES-256-GCM algoritmasına geçildi, aes key i ile veriler şifreleniyor, sadece key dpapi ile korunuyordu version ismi v10.
- Yıl 2024, Chromium ile aynı kullanıcı yetkisinde çalışan başka programların dpapi ile kolayca aes key ini çözüp verileri çalmasını önlemek için App-Bound Encryption yöntemine geçildi, version ismi v20.  

Aşağıda paylaşacağım kod bizzat 2008 ve 2019 yılları arasında, v10 gelmeden hemen önceki 79.0.3945.147 tag ındaki chromium sürümünün şifreleme ve deşifrelemeden sorumlu kısmına ait [components/os_crypt/os_crypt_win.cc](https://source.chromium.org/chromium/chromium/src/+/refs/tags/79.0.3945.147:components/os_crypt/os_crypt_win.cc)
```cpp
bool OSCrypt::EncryptString(const std::string& plaintext,
                            std::string* ciphertext) {
  DATA_BLOB input;
  input.pbData = const_cast<BYTE*>(
      reinterpret_cast<const BYTE*>(plaintext.data()));
  input.cbData = static_cast<DWORD>(plaintext.length());

  DATA_BLOB output;
  BOOL result =
      CryptProtectData(&input, L"", nullptr, nullptr, nullptr, 0, &output);
  if (!result) {
    PLOG(ERROR) << "Failed to encrypt";
    return false;
  }

  // this does a copy
  ciphertext->assign(reinterpret_cast<std::string::value_type*>(output.pbData),
                     output.cbData);

  LocalFree(output.pbData);
  return true;
}

bool OSCrypt::DecryptString(const std::string& ciphertext,
                            std::string* plaintext) {
  DATA_BLOB input;
  input.pbData = const_cast<BYTE*>(
      reinterpret_cast<const BYTE*>(ciphertext.data()));
  input.cbData = static_cast<DWORD>(ciphertext.length());

  DATA_BLOB output;
  BOOL result = CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                                   0, &output);
  if (!result) {
    PLOG(ERROR) << "Failed to decrypt";
    return false;
  }
```
Bu güzelim methodlarımız 2008 den 2019 yılına kadar böyleydi. Tek bir satır değişmedi. Peki sonra ne oldu? Her şey Windows da Chrome un yerel güvenliğini sağlamakla görevli, chromium projesinde codebase de os_crypt in windows bölümlerinden sorumlu [Will Harris](https://www.linkedin.com/in/wiharris/) in chromium un bug tracker domain i [issues.chromium.org](issues.chromium.org) a attığı bir [issue](https://issues.chromium.org/issues/40097413) ile başladı. Burda Will dpapi dll ine bağlı cryptprotectdata nın chrome sandbox unda çalışmadığından dem vuruyor. Chrome, network servisini sandbox a sokmak istiyor o zamana kadar sandbox ta olan servisler: Renderer, GPU, Utility, PPAP(plugin) idi. Network servisi işi gereği cookie lere erişen bir servis ve Windows da bunu yaptığında cookie ler şifreli tutulduğu için sandbox ortamında çalışırken hata veriyordu çünkü sandbox da dpapi çağrılarına izin yoktu. Bu issue nin özet akışını size türkçeleştirilmiş şekilde şöyle vermek istiyorum.  

## Yorum dizisi (kronolojik)

### #1 — wfh, 4 Eyl 2019 (açılış)
Network service sandbox içinde çalışırken cookie şifreleme `CryptProtectData` ile `0x80090345`
hatası veriyor; cookie'ler eklenemeden atlanıyor. "Network process düzgün sandbox'lanabilmeden
önce bu çözülmeli."

### #2 — mo@google, 5 Eyl (ilk beyin fırtınası)
"Şifreleme aslında her girdi için bir Windows servisine RPC. Çareyi bulamazsak her şeyi toplayıp
Mojo ile browser'a(browser servisi) gönderip orada şifreleriz — çirkin ama mümkün. Ya da şifrelemeyi tamamen
bırakabiliriz; Windows'ta değer kattığından emin değilim.(Neden böyle düşündüğünü CryptProtectData nın nasıl çalıştığını öğrendiğinizde anlayacaksınız)"

### #3 — wfh, 6 Eyl (çözümün tohumu)
"Browser process'te DPAPI ile bir anahtar saklayıp onu network process'e gönderip yerel şifrelemeyi
orada yapabiliriz. Her işlemde browser'a IPC'nin perf kaybını istemeyiz. Bu bug'ı ben alıyorum."

### #4 — mo, 11 Eyl (itiraz)
"Bu, mevcut cookie jar larını çözemez (onlar her girdide dpapi çağırıyor)." → Geriye dönük
uyumluluk endişesi.

### #5 — wfh, 1 Eki (deneyler + asıl plan)
"Warmup fikri olmadı — integrity level sandbox'ta DPAPI'yi blokluyor. Seçenekler: her çağrıda
IPC, sandbox intercept, ya da oscrypt'i session key kullanacak şekilde yeniden yazmak (rekey gerektirir).
Plan: iki mekanizmayı bir arada tut, kullanıcıları yeni anahtara migre et, sonra eskiyi kaldır,
sonra sandbox'ı aç. Yan etki: perf artışı."

### #6 — rs, 1 Eki
"macOS'te yaptığımızı tekrar kullanabilir miyiz? Browser process anahtarı `network_service.mojom`
üzerinden geçiriyor."

### #7 — wfh, 1 Eki (iki adımlı plan)
"Adım 1: oscrypt'i şifrelemeyi kendimiz yapacak ama anahtarı DPAPI'de saklayacak şekilde değiştir;
veriye 'magic signature' koyarak migre et (→ `v10`). Adım 2: `SetEncryptionKey` mojo mesajıyla
anahtara ihtiyaç duyan process'lerde oscrypt'i başlat."

### #8 — wfh, 3 Eki
Migrasyon stratejisi karmaşık olabileceği için bir tasarım dokümanı yazdı.([dökümanın linki](https://docs.google.com/document/d/11rp7qkTYGythyKgjvmmkII9wySvXkM9uYM6cPmchJ1U/edit?tab=t.0#))

### #9 — wfh, 5 Eki
Bug "Accepted". Bu değişikliğin kıracağı testlerin listesi (EncryptedCookies, SessionCookies,
BasicCookies vb.).

### #10–#11 — wfh, 9/15 Eki
(Monorail migrasyonundan kalma boş yorumlar.)

### #12 — bot, 21 Eki (ASIL COMMIT İNDİ)
Commit `265b39473...` indi. os_crypt_win.cc'nin yanı sıra network service tarafını da değiştirdi:
`network_service.cc/.h`, `network_service.mojom` (SetEncryptionKey), `chrome_browser_main_win.cc`,
`system_network_context_manager.cc`. v10 motoru + anahtarın network process'e taşınması aynı CL'de.

### #13 — wfh, 21 Eki (hemen sorun çıktı)
"Tek-process network'te beklenen bir DCHECK'e yol açıyor. Düzeltici follow-up CL indireceğim."

### #14–#15 — 21 Eki
Follow-up commit `76f496a...`: "Aynı process'te os_crypt anahtarını iki kez set etmeye tolerans
göster" — in-process network ve `--single-process` modundaki çökmeyi düzeltiyor.

### #16 — bot, 23 Eki (geri alma)
O follow-up revert edildi: "Farklı bir yaklaşıma karar verildi; başka bir CL bunu os_crypt
davranışına dayanmadan daha iyi çözüyor."

### #17 — wfh, 29 Eki (Canary'de doğrulama)
"Değişiklik Canary'de cookie okuma hatalarında anlamlı fark yaratmadı (bir şey bozmadı). Cookie DB
okumasında perf artışı: öncesi %50'de 132.8ms, sonrası 105.5ms → %7-20 iyileşme. Sıradaki CL'ler
cookie verisinin zorunlu migrasyonu olacak."

### #18 — wfh, 22 Şub 2021
"Fixed olarak işaretlendi."

### #19 — bot, 25 Şub 2021 (son halka)
Cookie'lerin tek seferlik migrasyonu (`db327569...`): şifreli cookie'ler yeni anahtarla yeniden
şifrelenip geri yazılıyor, cookie DB v14'e yükseltiliyor — "böylece gelecekte network process
sandbox'lı çalışabilir."

### #20 — 25 Şub 2021
Kayıt Monorail'den yeni tracker'a migre edildi.

İssue nin konuşma zincirinden ne anladığınızı doğrulamak için kısaca özet geçmek gerekirse; mo ilk başta her şifreleme gerektiğinde browser process e (asla sandbox da olmaz, kemik process çünkü) gönderelim o yapsın diyor. Sonra wfh bunun haklı olarak performans kaybına yol açacağını söyleyip daha akılcıl bir çözüm buluyor oda bir anahtar oluşturmak ve her şeyi onla şifrelemek o anahtarı da dpapi ile korumak. Böylece aslında network servisinin sandbox da doğru çalışmasını sağlamanın ötesinde şifreleme işleminide daha verimli hale getirmiş oluyorlar ki Cookie DB de oluşan performans artışından da konuşmanın ilerleyen kısımlarında bahsediliyor. Böylece bizim bugün versiyon v10 olarak bildiğimiz os_crypt yöntemi doğuyor. Bu şifreleme yöntemini kullanan ilk stabil chromium ise chrome 80 olarak bildiğimiz ürün. Şimdi bu haline bakalım. Aşağıda chrome 80 in 80.0.3987.100 tag lı ilk sürümündeki [components/os_crypt/os_crypt_win.cc](https://source.chromium.org/chromium/chromium/src/+/refs/tags/80.0.3987.100:components/os_crypt/os_crypt_win.cc;bpv=0;bpt=0) kodu göreceksiniz:  

```cpp
bool OSCrypt::EncryptString(const std::string& plaintext,
                            std::string* ciphertext) {
  if (g_use_legacy)
    return EncryptStringWithDPAPI(plaintext, ciphertext);

  crypto::Aead aead(crypto::Aead::AES_256_GCM);

  auto key = GetEncryptionKeyInternal();
  aead.Init(&key);

  // Note: can only check these once AEAD is initialized.
  DCHECK_EQ(kKeyLength, aead.KeyLength());
  DCHECK_EQ(kNonceLength, aead.NonceLength());

  std::string nonce;
  crypto::RandBytes(base::WriteInto(&nonce, kNonceLength + 1), kNonceLength);

  if (!aead.Seal(plaintext, nonce, std::string(), ciphertext))
    return false;

  ciphertext->insert(0, nonce);
  ciphertext->insert(0, kEncryptionVersionPrefix);
  return true;
}

bool OSCrypt::DecryptString(const std::string& ciphertext,
                            std::string* plaintext) {
  if (!base::StartsWith(ciphertext, kEncryptionVersionPrefix,
                        base::CompareCase::SENSITIVE))
    return DecryptStringWithDPAPI(ciphertext, plaintext);

  crypto::Aead aead(crypto::Aead::AES_256_GCM);

  auto key = GetEncryptionKeyInternal();
  aead.Init(&key);

  // Obtain the nonce.
  std::string nonce =
      ciphertext.substr(sizeof(kEncryptionVersionPrefix) - 1, kNonceLength);
  // Strip off the versioning prefix before decrypting.
  std::string raw_ciphertext =
      ciphertext.substr(kNonceLength + (sizeof(kEncryptionVersionPrefix) - 1));

  return aead.Open(raw_ciphertext, nonce, std::string(), plaintext);
}
```

Bu sefer veriyi şifrelerken direkt dpapi cryptprotectdata yı çağırmıyoruz. Onun yerine bir aes 256 key i kullanıyoruz. İşte bu key artık dpapi cryptprotectdata ile User Data altında Local State dosyasında saklanıyor. Kodda göze çarpan bir detay decrypt methodunda, Eğer şifresi çözülecek blob kEncryptionVersionPrefix("v10") ile başlamıyorsa onu gene eski yöntemle yani direkt dpapi kullanarak çözüyoruz. Bu hala cookie çözmek için network servisinin dpapi çağırmasına sebep olacak. Yani aslında sandbox problemi hala çözülmemiş eski verilerin geri çözülebilmesi için bir geriye dönük uyumluluk kodu bırakılmış. Sonraki süreçte eğer issue yorumlarında 19. mesaja bakarsanız cookie db için 2021 yılında bir migration çıktığını göreceksiniz bu başında v10 olmayan tüm verileri çözüp tekrar v10 ile şifreleyip geri kaydeden ek bir kodu içeriyor, buda tüm şifreli verilerin v10 a geçişini hızlandırmak için yapıldı. Günümüzde böyle bir destek yok yani ya v10 ya v20 kullanabiliyoruz. Hangisini kullanacağına Chromium çalışma esnasında karar veriyor. eğer v20 nin yeterlilikleri sağlanıyorsa tercih her zaman v20 yönünde çünkü daha güvenli, öteki türlü güvenli limanımız v10 u kullanıyoruz o her türlü iş yapıyor zaten ama daha az güvenli.  

# V10 - Aynı Kullanıcı Hesabı Temelli Koruma

Biz v10 dan başlayalım. Ondan öncesinde ciddli bir yapı yok gördük basitçe dpapi ile veriyi şifreliyoruz ve aynı şekilde çözüyoruz. v10 da çok karmaşık sayılmaz aslında ki yukarda da değindim. Ama genede v10 a ayrı bir başlık açmama ve direkt v20 ye geçmememe sebep olan şey benim sadece Chromium codebase i üzerinden bu korumayı anlatmak istememem. Beraber Windows Internals a girelim ve gerçekten bu kripto fonksiyonlarını Windows nasıl tasarlamış bakalım istiyorum.  

## Chromium codebase i

Chromium un en güncel versiyonuna bakarsak ki benim bu yazıdaki referans tag ım 159.0.8129.1, v10 ile ilgili her şeyin codebase deki [components/os_crypt/async](https://source.chromium.org/chromium/chromium/src/+/main:components/os_crypt/async/;bpv=0;bpt=0) dizinin altında olduğunu göreceksiniz. Burda yaptığımız okumalarla v10 un özelliklerini maddeler halinde sıralayabiliriz:  
- async bir crypt mekanizmasına uyum sağlatılmaya çalışılıyor, eskiden sync kısmıda varmış kaldırılmış
- dpapi crytprotectdata ile şifrelenen key base64encode lanıp "User Data" altında "Local State" dosyasında os_crypt.encrypted_key entry sinde tutuluyor, cryptunprotectdata ile çözülüyor. (browser/dpapi_key_provider.cc:GetKeyInternal, DecryptKeyWithDPAPI)
- Bu key ile şifrelenen verilerin başında "v10" prefix i var, şifrelenen verilerde base64encode lanıyor. [components/os_crypt/async/common/encryptor.cc:Encryptor::DecryptData]
- şifreleme yöntemi aes-256-gcm [components/os_crypt/async/common/encryptor.cc:Encryptor::Key::Encrypt]
- daha önceden şifrelenen bir veri o chrome runtime ında encryption için tercih edilen provider değilse (provider dan kasıt v10 ve v20) veri ile birlikte gelen should_reencrypt flag ı tiklenir bu flag ı kontrol eden kod parçaları veriyi tekrar şifreler. Örnek (chrome/browser/enterprise/encryption/cache_encryption_provider_impl.cc):  
```cpp
...
os_crypt_async::Encryptor::DecryptFlags flags;
    std::optional<std::string> decrypted =
        encryptor->DecryptData(encrypted_primary_key_, &flags);
    if (decrypted && decrypted->length() == kPrimaryKeySizeInBytes) {
      base::UmaHistogramBoolean(
          "Enterprise.EncryptedCache.KeyRetrievalFromPrefsSuccess", true);
      DVLOG(1)
          << "Successfully validated existing encrypted cache encryption key.";
      needs_new_key = false;

      // If the key is valid, but needs to be re-encrypted, then do so.
      if (flags.should_reencrypt) {
        DVLOG(1) << "Re-encrypting cache encryption key.";
        std::optional<std::vector<uint8_t>> encrypted =
            encryptor->EncryptString(*decrypted);
            ...
```
- key Chrome memory sinde plain olarak tutulmuyor. CryptProtectMemory adında aslında sadece bir RtlEncryptMemory sarmalayıcısı olan Windows API si ile memory de şifreli olarak tutuluyor ve şifreleme için kullanılacağı Zaman CryptUnprotectMemory ile çözülüp kullanılıyor. (components/os_crypt/async/common/encryptor.cc:Encryptor::Key::Encrypt)

Tamam veriler AES-256-GCM key ile şifreleniyor, veriyi şifreleyen key ise bir sefer oluşturulup sonra dpapi ile şifrelenip "Local State" dosyasında tutuluyor. Buraya kadar Chromium tarafını inceledik şimdi Windows un aes key ini dpapi ile nasıl şifrelediğini inceleyelim.

## Windows CryptProtect/UnprotectData tersine mühendisliği

Şifreleme yolunun özet akışı şu şekilde:  
CryptProtectData (input validasyonu ve isteğe bağlı kullanıcıya onay veya ekstra girdi prompt u) -> CryptProtectDataNoUI(veriyi RPC aktarımı esnasında şifrelemek için RtlEncryptMemory, RPC hattı üzerinden dpapisrv nin s_SSCryptProtectData fonksiyonuna teslim) -> s_SSCryptProtectData(kontrol ve kurulum, veriyi esas şifreleme fonksiyonuna iletme) -> SPCryptProtect(RtlDecryptMemory ile veriyi çözme sonra masterkey ile şifreleme) -> (şifrelenen veri geri döner)

Encryption zincirinden başlayalım zaten diğeride onun simetrik tersi olacak. İlk hedef crypt32.dll indeki CryptProtectdata fonksiyonu. Bu fonksiyon key i şifrelemek için kullandığımız fonksiyon.  
Yaptığı tek şey prompt göstermesi gerekip gerekmediğini kontrol etmek (evet bu fonksiyon normalde kullanıcıya prompt da gösteriyor bir izin mahiyetinde hatta istersek bu prompt da kullanıcıdan girdi de alabiliyoruz bu girdi de birazdan göreceğimiz entropy2 argümanı olarak şifreleme işlemine dahil ediliyor)

Fonksiyonun imzası şu şekilde:  
```c
DPAPI_IMP BOOL CryptProtectData(
  [in]           DATA_BLOB                 *pDataIn,/*şifrelenecek veri*/
  [in, optional] LPCWSTR                   szDataDescr,/*bu verinin özeti(prompt gösterilecekse 
                                                            bu özet yazısı kullanıcıya gösteriliyor)*/
  [in, optional] DATA_BLOB                 *pOptionalEntropy,/*şifrelemeye ekstra girdi*/
  [in]           PVOID                     pvReserved,/*şimdilik bizi bağlamıyor*/
  [in, optional] CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,/*prompt detayları(olacaksa)*/
  [in]           DWORD                     dwFlags,/*Genel flag lar*/
  [out]          DATA_BLOB                 *pDataOut/*şifrelenmiş veri*/
);
```

Prompt gösterme ve onaylama hatta prompt ile istersek dediğim gibi girdi de alabiliyoruz kullanıcıdan, bunları tamamladıktan sonra esas şifreleme işlemi için argümanlar bir sonraki fonksiyonumuz olan CryptProtectDataNoUI ye devrediliyor:

```c
BOOL CryptProtectDataNoUI (
  DATA_BLOB * pDataIn,
  LPCWSTR szDataDescr,
  DATA_BLOB * pOptionalEntropy,
  PVOID pvReserved,
  CRYPTPROTECT_PROMPTSTRUCT * pPromptStruct,
  DWORD dwFlags,
  PVOID pvEntropy2,
  DWORD cbEntropy2,
  DATA_BLOB * pDataOut
)
```

Gördüğünüz üzere tek fark entropy2 nin gelmesi o da duruma bağlı prompt dan geliyor yukarda söylediğim gibi. Peki bu fonksiyon ne yapıyor? dpapi.dll de tanımlı bu fonksiyon esas işlevi yerine getirecek olan dpapisrv.dll ile iletişim kurup rpc üzerinden şifrelenecek veriyi LSASS(Local Security Authority Subsystem Service) e aktarma görevini üstleniyor. Burda lsass ne buna girmicem ama Windows un kritik process lerinden biri olduğunu çok sıkı korunduğunu ve temel amacının bilgisayarınızdaki lokal oturum işlemlerini doğrulamak ve yönetmek olduğunu söyleyebilirim. Peki neden lsass katına çıktık. Çıktık evet çünkü lsass hassas bilgiler içeren bir process, kullanıcı masterkey leri gibi... Bizim masterkey ile işimiz var birader çünkü amacımız kullanıcıya sadece kendinin şifresini çözebildiği bir şifreleme hizmeti vermek. Masterkey lerde bunun için var. Şuan açıp bakabilirsiniz %APPDATA%\Microsoft\Protect dizini altında kullanıcı SID inizin olduğu dosyada masterkey leriniz bulunur (bunları görmek için explorer da sistem dosyalarını gör ayarını yapmanız lazım). Bu dosyalarda masterkey leriniz şifreli olarak tutulur ve bu şifrenin anahtarı da sizin kullanıcı parolanızdır. Tabii çok değişken durumlar var MSA ile oturum açmış olabilirsiniz, PIN ile oturum açmış olabilirsiniz, bir domain ağındaki bir kullanıcı olabilirsiniz biz bu seçenekleri şimdilik kapatalım. Local bir kullanıcı hesabınızın olduğu en basit senaryoyu konuşalım.  

CryptProtectDataNoUI RPC ile ncalrpc:protected_storage e bağlanır bu lsass process inde çalışan dpapisrv.dll in dinlediği hattır. Sonra sırayla SystemFunction040 ve NdrClientCall3 fonksiyonlarını çalıştırır. NdrClientCall3 şifrelenecek veriyi dpapisrv nin ilgili interface inin hedef fonksiyonuna (opnum->0) gönderir ve cevabı dpapisrv den bekler. Ondan önce SystemFunction040 diye gözüken ama esas adı RtlEncryptMemory olan fonksiyon ise yola çıkacak plaintext imizi yani şifrelenecek verimizi yol için şifreler, bu işlem için veri kernel deki ksecdd(Kernel Security Support Provider Interface) e gider, ksecdd de abisine yani CNG.sys(Cryptographic Next Generation) driver a gider. CNG her boot timeda rastgele oluşturulan anahtarları veriyi şifrelemek için kullanır.   
```c
undefined8 CngEncryptMemoryInitialize(void){
  ...
  uVar1 = SystemPrng(local_28,0x18);
  if (uVar1 != 0) {
    lVar3 = 0x10;
    uVar1 = SystemPrng(local_48,0x10);
    if ((uVar1 != 0) && (uVar1 = SystemPrng(&local_38,0x10), uVar1 != 0)) {
  ...
```

O yüzden CngEncryptMemory ile şifrelenen veri bilgisayar kapatılıp açılınca geri çevrilemez çünkü yeni random anahtarlar oluşturulmuştur. RtlEncDec kısa vaadeli şifrelemeler için kullanılır. Burda amacımız RPC üzerinden şifrelenecek verimizi dpapisrv a güvenli şekilde taşımak olduğu için kullanımı anlamlıdır.  
RtlEncDecMemory api lerinin 4 adet şifreleme modu vardır. Bunlar: Same Process, Cross Process, Same Logon ve System dir.  
Same Process modu veriyi api yi çağıran process in kimliğinide kullanarak şifreler böylece sadece o process bu şifreyi çözebilir olur.  
Cross Process veriyi şifrelerken ekstra anahtar kullanmaz o yüzden herkes çözebilir olur.  
Same Logon veriyi Logon LUID ile şifreler böylece o oturumdaki o kullanıcını yetkisi ile çalışan process ler şifreyi çözebilir.  
System ise adından da anlaşılacağı gibi veriyi sadece System kullanıcısının deşifre edebilmesini sağlar bunun için veriyi çözerken çözmek isteyen yani api yi çağıran thread in access token ine bakar. System token i değilse veriyi çözmez.  

CNG şifrelenecek veri boyutu eğer 16 nın katı ise AES-128-CBC, 8 in katı ise 3DES kullanır. Sizin ekstra bir padding yapmanıza gerek yok veri 8 er byte a bölünecek şekilde zaten SystemFunction040/RtlEncryptMemory e girmeden önce CryptProtectDataNoUI de padding ediliyor. Bu detayları sizi çok sevdiğim için veriyorum bu arada.  
Mekanizmanın nasıl çalıştığını kendi gözlerinizle görmek istiyorsanız RtlEncrypt/DecryptMemory fonksiyonlarının bu macerasını python kodu ile simüle ettiğim aşağıdaki kod ile oynayabilirsiniz. Tabii sisteminizdeki gerçek şifreli verileri çözmek için kernel memory nizden Yukardaki kodda gördüğünüz 3 SystemPrng çıktısını almanız lazım. Bu işi WinDbg ile bu çıktıların saklandığı offset leri dump layarak yapabilirsiniz. 
```powershell
PS C:\Users\sems\Desktop\codepy\os_crypt> python .\cng_encdec_memory.py encrypt --root 775fc4584823dcae043dca33853900a404de03c2e96af6fb --iv 0f91d1c3cf88ead4ec856938f6d694a6 --cross 7bc4ed1bdd86ab6697621434bd6f913f --text "selam" --scope same_logon
[*] padded input: 73656c616d0000000000000000000000
d79212e7c0022600c94b00f549c656bd

PS C:\Users\sems\Desktop\codepy\os_crypt> python .\cng_encdec_memory.py decrypt --root 775fc4584823dcae043dca33853900a404de03c2e96af6fb --iv 0f91d1c3cf88ead4ec856938f6d694a6 --cross 7bc4ed1bdd86ab6697621434bd6f913f --hex d79212e7c0022600c94b00f549c656bd --scope same_logon
73656c616d0000000000000000000000
```

RtlEncryptMemory ile şifrelenen veri RPC üzerinden dpapisrv deki hedef fonksina yani s_SSCryptProtectData ya gider. Burda önce yol için şifrelenmiş veri geri çözülecek sonrada esas şifreleme işlemi veriye uygulanacaktır. Geri çözme işlemi için basitçe RtlDecryptMemory çağırmak işe yaramaz çünkü veri dpapi.dll de  RtlEncryptMemory ile şifrelenirken SAME_LOGON moduyla şifrelendi. Yani sadece aynı kullanıcı yetkisi ile şifre çözülebilir. Amma ve lakin dpapi.dll bizi program process imizde çalıştı, dpapisrv ise System kullanıcısı yetkisi ile çalışır. Bu yüzden dpapisrv veriyi çözmeden önce RpcImpersonateClient api si ile istemcinin access token ine bürünür RtlDecryptMemory ile veriyi çözer sonrada hemen eski access token ine RevertToSelf ile kavuşur. İnce ama gerekli bir ara hamledir.  

Artık veri şifrelenmeye hazır. Şifreleme için birçok farklı seçenek mevcut, tabii CryptProtectData yı dümdüz kullanırsanız Windows en "güçlü" sünü sizin için seçecek buda AES-256-CBC oluyor, iv imiz ise "0" güvenliksiz geliyor evet ama key öyle bir random oluştuluyorki iv e gerek kalmıyor gibi düşünebilirsiniz. AES key ini besleyen deterministik tek veri ise masterkey, masterkey şifreli olarak tutulduğu yerden çıkarılıyor ve LSASS tarafından bu şifre çözülüyor çünkü LSASS de oturum açan kullanıcının giriş şifresinin hash leri var. Bu hash ler şifreli masterkey i çözmek ve şifrelemek için kullanılıyor böylece kullanıcı ile masterkey birbirine bağlanmış oluyor. Masterkey ile veri şifreleniyor. Şifreli veri aynı RPC hattı üzerinden istemciye dönüyor. İşte CryptProtectData böyle çalışıyor.  
Beraber gerçekten sistemi doğru anlayıp anlamadığımızı test etmek için bu akışı python ile birlikte simüle edelim. Bu simülasyonda RtlEncDecMemory olmayacak çünkü biz veriyi gerçek anlamda RPC üzerinden LSASS e iletmicez. LSASS tarafında yada istemci tarafında uygulanan kriptolojik adımları taklit edicez. Kodlarda kullanılan tüm kütüphaneleri yazının sonunda bulabilirsiniz, buraları şişirmesin diye en sona koymaya karar verdim. İlk başta basitçe CryptProtectData yı çağırıp ondan dönen şifreli blob ı inceleyelim.  

```powershell
PS C:\Users\sems\Desktop\codepy\os_crypt> python .\dpapi_trigger.py protect --text "selam"
01000000d08c9ddf0115d1118c7a00c04fc297eb010000009741565fe6816442aecf3e6f9d2b508300000000020000000000106600000001000020000000dc5d77387aa40da3e1bd16cc99192833ad16a1d52957637e6fbc5ef2b7f27e9a000000000e8000000002000020000000206d95ce9728b37e33d77c09acb1db8eac8a4198ddcbec13e5453d3233fb43c11000000010c9452cbadf6e380a1d7472fa7def014000000093a3655784e2a352863aea0975ce4750c4c1226adb924ddbd28389461c6459e4ae0e93fdf3a8c9e82704bd3455b44482fc26136993e8d8544e713884a3af0d39
```

dpapi_trigger.py CryptProtectDataNoUI API sini kullanarak verimizi şifreledi. Ve bize bir DPAPI blob u verdi. Bu blob un anatomisini inceleyelim şimdi.  

```powershell
PS C:\Users\sems\Desktop\codepy\os_crypt> python .\dpapi_protect.py parse-blob --blob 01000000d08c9ddf0115d1118c7a00c04fc297eb010000009741565fe6816442aecf3e6f9d2b508300000000020000000000106600000001000020000000dc5d77387aa40da3e1bd16cc99192833ad16a1d52957637e6fbc5ef2b7f27e9a000000000e8000000002000020000000206d95ce9728b37e33d77c09acb1db8eac8a4198ddcbec13e5453d3233fb43c11000000010c9452cbadf6e380a1d7472fa7def014000000093a3655784e2a352863aea0975ce4750c4c1226adb924ddbd28389461c6459e4ae0e93fdf3a8c9e82704bd3455b44482fc26136993e8d8544e713884a3af0d39
DPAPI blob - 230 bytes
  version        : 1
  provider       : df9d8cd0-1501-11d1-8c7a-00c04fc297eb (DPAPI)
  mk version     : 1
  master-key GUID: 5f564197-81e6-4264-aecf-3e6f9d2b5083 - the master key that protects this blob
  flags          : 0x00000000  (none)
  description    : ''
  cipher         : 0x6610  AES-256 (256 bit)
  salt (32 B)    : dc5d77387aa40da3e1bd16cc99192833ad16a1d52957637e6fbc5ef2b7f27e9a
  hmac key (0 B) : (empty)
  hash           : 0x800e  SHA512 (512 bit)
  mac salt (32 B): 206d95ce9728b37e33d77c09acb1db8eac8a4198ddcbec13e5453d3233fb43c1
  ciphertext(16B): 10c9452cbadf6e380a1d7472fa7def01
  MAC (64 B)     : 93a3655784e2a352863aea0975ce4750c4c1226adb924ddbd28389461c6459e4ae0e93fdf3a8c9e82704bd3455b44482fc26136993e8d8544e713884a3af0d39
```

Burda bizim için çok önemli bilgiler var bikere blob un DPAPI blob u olduğunu provider kısmındaki GUID den teyit etmiş oluyoruz. Bu blob u şifrelemek için kullanılan masterkey in versiyonunu ve masterkey in GUID ini görüyoruz ki bu GUID şifreyi çözmek için hangi masterkey i kullanmamız gerektiğini bulmamız açısından kritik. flags kısmı şimdilik boş çünkü ekstra bir flag vermedik. description kısmıda boş bu blob a ekleyebildiğimiz düz bir metin olabilirdi, blob u açıklamak için. Chromium da yukarda bahsettiğim en son tag ında bunların kullanıldığını görebilirsiniz:  
```cpp
  result = ::CryptProtectData(
      /*pDataIn=*/&input,
      /*szDataDescr=*/
      base::SysUTF8ToWide(
          base::StrCat(
              {version_info::GetProductName(),
               version_info::IsOfficialBuild() ? "" : " (Developer Build)"}))
          .c_str(),
      /*pOptionalEntropy=*/nullptr,
      /*pvReserved=*/nullptr,
      /*pPromptStruct=*/nullptr, /*dwFlags=*/CRYPTPROTECT_AUDIT,
      /*pDataOut=*/&output);
```

description da ürün versiyonu var, flag olarak AUDIT flag ı özel bir ETW logu tutuyor böylece description filtrelenerek ETW de bu spesifik kod bloğu ne sıklıkla çağrılmış Chromium bunu denetleyebiliyor.  
Cipher ve verify kısımlarını geçiyorum en altta da masterkey imizle şifrelenmiş veriyi görüyorsunuz. Şimdi çok havalı bir şey yapıcaz ve hiçbir Windows API si kullanmadan bu blob u kendimi çözmeye çalışıcaz. Bunun için öncelikle hedef masterkey e ulaşmamız lazım. Python process ini kendi local hesap kullanıcımla çalıştırdığım için kullanılan masterkey in benim appdata mda olması gerekiyor hemen bakalım.  
"C:\Users\sems\AppData\Roaming\Microsoft\Protect\S-1-5-21-2551214374-3482223478-886197384-1001" bu dosya yoluna baktığımda burda bissürü stored masterkey file olduğunu görüyorum:  

![stored_masterkeys](/pictures/chromium/stored_masterkeys.png)

Bu dosyaların herbirinde farklı bir masterkey im var, birden fazla dosya ve masterkey olmasının sebebi masterkey lerin işletim sistemi tarafından belli süre aralıkları yada belli event lere bağlı olarak değiştirilmesi. Siz veriyi şifrelemek istediğinizde her zaman güncel masterkey i kullanır CryptProtectData onunda adı "Preffered" isimli dosyada tutuluyor. Lakin eski bir masterkey ile şifrelenmiş olabileceğinden CryptUnprotectData blob daki mkguid e bakıp o masterkey ile şifreyi çözmeye çalışır. Eğer kullanıcı parolanızı değiştirirseniz tüm stored masterkey file larınız önce eski şifreniz ile çözülür sonra yeni şifreniz ile tekrar şifrelenir tabii bazen bu işlem aksayabilir o durumlarda da CREDHIST adında bir dosyaya başvurursunuz. Bu dosyada bir önceki parolanız bir sonraki parolanıza bağlanır. Yani şimdiyi biliyorsanız bir adım önceki parolanızı de aslında biliyor olursunuz. Tabii parolarınız hiçbir zaman raw durmaz parola hash lerinden bahsediyorum parola derken zaten stored masterkey file larda parola larla değil parola hash leri ile şifrelenir bu akıldan çıkmasın. Esas parolanızı Windows hiçbir zaman ortalıkta çıplak tutmaz. Blob da gördüğümüz mkguid hemen gözüme çarpıyor. Şimdi biz kendimize gereken masterkey i çıkartalım bakalım:  
```powershell
PS C:\Users\sems\Desktop\codepy\os_crypt> python .\masterkey.py "C:\Users\sems\AppData\Roaming\Microsoft\Protect\S-1-5-21-2551214374-3482223478-886197384-1001\5f564197-81e6-4264-aecf-3e6f9d2b5083" --password 442027 --sid S-1-5-21-2551214374-3482223478-886197384-1001
[*] opened with: current password
[*] master key : c684a7de467f3f71cabd92f399b634eff0428b330b8aa99bef2c84a518664941ca00d2cb3a24e5e71066e1c430fdfdbe8c6b2e9e2daf2b21d9cb52f017d7e618
```

İşte bu kadar:D argümanlardan biri local hesabımın şifresi diğeri de SID yani kullanıcı adıma(sems) işletim sisteminin verdiği sayısal sabit değer. Bu ikisi şifreyi çözmek için kullanılıyor. Stored masterkey file de masterkey in farklı şekillerde şifrelenmiş versiyonları mevcut biz local hesap bilgilerimizle çözebildiğimiz masterkey_blob u çözdük ama tek seçenek bu değil. backupkey ilede çözebilirdik yada domainkey ile. Yani bu file da aynı masterkey 3 farklı şekilde şifreleniyor. Ne yazıkki benim tool şimdilik sadece birisi ile çözüm yapabiliyor.  

Artık elimizde masterkey olduğuna göre dpapi_trigger ile şifrelediğimiz veriyi manuel olarak çözebiliriz. dpapi_protect bu işi yapacak.  
```powershell
PS C:\Users\sems\Desktop\codepy\os_crypt> python .\dpapi_protect.py unprotect --blob 01000000d08c9ddf0115d1118c7a00c04fc297eb010000009741565fe6816442aecf3e6f9d2b508300000000020000000000106600000001000020000000dc5d77387aa40da3e1bd16cc99192833ad16a1d52957637e6fbc5ef2b7f27e9a000000000e8000000002000020000000206d95ce9728b37e33d77c09acb1db8eac8a4198ddcbec13e5453d3233fb43c11000000010c9452cbadf6e380a1d7472fa7def014000000093a3655784e2a352863aea0975ce4750c4c1226adb924ddbd28389461c6459e4ae0e93fdf3a8c9e82704bd3455b44482fc26136993e8d8544e713884a3af0d39 --master-key c684a7de467f3f71cabd92f399b634eff0428b330b8aa99bef2c84a518664941ca00d2cb3a24e5e71066e1c430fdfdbe8c6b2e9e2daf2b21d9cb52f017d7e618
[*] mac_ok: True  descr: 
[*] plaintext (5 B): 73656c616d
selam
```
İsterseniz aynı işlemi entropy1 ve entropy2 argümanları ile yapadabilirsiniz, öyle yaparsanız çözerken entropy girdilerinide dpapi_protect e vermeniz lazım yoksa veri çözülemez. Description da verebilirsiniz. kafanıza göre.  

Tabii başka yollarda var. Bildiğiniz gibi bilgisayarımızdaki tüm kullanıcılar bildiğimiz anlamda parola ya sahip değiller. Mesela System kullanıcısı, o bir veriyi şifrelemek istediğinde ne oluyor dersiniz? Yada Local Machine. Bunlar nasıl DPAPI yi kullanıyor? Çözüm şöyle geliştirilmiş. LSASS da tutulan kritik bir bilgi daha var. Buna DPAPI_SYSTEM deniliyor. 44 byte lık bir veri bu. ilk 4 byte versiyon sonraki 20 byte ı machine sırrı diğer 20byte ı user sırrı diye geçiyor. machine sırrı benim gördüğüm kadarıyla sadece Local Machine nin masterkey leri için kullanılıyor user sırrı ise parolası olmayan bir takım kullanıcılar için System gibi. Kafalar çok karışmadan bir deney daha yapalım. Öncelikle System kullanıcı olarak CryptProtectData yı tetikleyelim.  

Bunun için sysinternals tool larından biri olan PsExec i kullanıcam -s argümanı system kullanıcısının komut çalıştırmasını sağlıyor.  
```cmd
C:\Users\sems\Desktop\codepy\os_crypt>psexec -s python "C:\Users\sems\Desktop\codepy\os_crypt\dpapi_trigger.py" protect --text "ben sistemim"

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com


01000000d08c9ddf0115d1118c7a00c04fc297eb01000000bdc9d9bffd04e841a8d9168b8a5f4d95000000000200000000001066000000010000200000001b97fdf3759fd26dfdc179f99c51a98d37a7327278b5f1d4c05db22a3d3f2dc3000000000e80000000020000200000006c2394d7cedd166e0a0644600901672cb9eb885fbd05c20b4fd931e742e133ba1000000002ca6441d5aea2309ee4fad2ab83f810400000002d296c6be1a553e73994a736798a7ac1a2eaa48b0cfb740b9b1bf0a3b8eb54665d943146d890e1d6bece9e94d326d83be149568fe984567ae49d0594c8b813f2
```

Bu blob artık System kullanıcısının masterkey i ile şifrelendi. Bunu doğrulamak için blob un mkguid ini analiz edelim.  

```powershell
PS C:\Users\sems\Desktop\codepy\os_crypt> python .\dpapi_protect.py parse-blob --blob 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000bdc9d9bffd04e841a8d9168b8a5f4d95000000000200000000001066000000010000200000001b97fdf3759fd26dfdc179f99c51a98d37a7327278b5f1d4c05db22a3d3f2dc3000000000e80000000020000200000006c2394d7cedd166e0a0644600901672cb9eb885fbd05c20b4fd931e742e133ba1000000002ca6441d5aea2309ee4fad2ab83f810400000002d296c6be1a553e73994a736798a7ac1a2eaa48b0cfb740b9b1bf0a3b8eb54665d943146d890e1d6bece9e94d326d83be149568fe984567ae49d0594c8b813f2
DPAPI blob - 230 bytes
  version        : 1
  provider       : df9d8cd0-1501-11d1-8c7a-00c04fc297eb (DPAPI)
  mk version     : 1
  master-key GUID: bfd9c9bd-04fd-41e8-a8d9-168b8a5f4d95 - the master key that protects this blob
  flags          : 0x00000000  (none)
  description    : ''
  cipher         : 0x6610  AES-256 (256 bit)
  salt (32 B)    : 1b97fdf3759fd26dfdc179f99c51a98d37a7327278b5f1d4c05db22a3d3f2dc3
  hmac key (0 B) : (empty)
  hash           : 0x800e  SHA512 (512 bit)
  mac salt (32 B): 6c2394d7cedd166e0a0644600901672cb9eb885fbd05c20b4fd931e742e133ba
  ciphertext(16B): 02ca6441d5aea2309ee4fad2ab83f810
  MAC (64 B)     : 2d296c6be1a553e73994a736798a7ac1a2eaa48b0cfb740b9b1bf0a3b8eb54665d943146d890e1d6bece9e94d326d83be149568fe984567ae49d0594c8b813f2
```

masterkey GUID i benim Protect dizinimde olan hiçbir stored masterkey file dosyasının ismi ile uyuşmuyor. Şimdi sistem in Protect dizinine gidelim.  
"C:\WINDOWS\System32\Microsoft\Protect\S-1-5-18\User":  

![system_protect](/pictures/chromium/system_protect.png)

Neden bu dizin diye bana sormayın adamlar böyle karar vermiş yoksa System in AppData sının burası olmadığını bende biliyorum. Yapacak bir şey yok.  Gördüğünüz gibi "df9d8cd0-1501-11d1-8c7a-00c04fc297eb" mkguid imizi bulduk. Şimdi onu kırmaya çalışıcaz ama elimizde az önce bahsettiğim DPAPI_SYSTEM verisi yok. Aslında var. Ama yönetici yetkimiz olabilirse var. Bunun için tabii birçok farklı yöntem var. Ben benim kullandığımı göstericem size.  

```cmd
C:\Users\sems\Desktop\codepy\os_crypt>reg save HKLM\SYSTEM   SYSTEM
The operation completed successfully.

C:\Users\sems\Desktop\codepy\os_crypt>reg save HKLM\SECURITY SECURITY
The operation completed successfully.
```

bu registry hive lerini çıkartıyoruz, işte burda yönetici yetkisi lazım sonrası gene normal kullanıcı ile oluyor. Çıkarttığımız hive leri lsa_secrets.py mize atıyoruz oda crawl eyliyor:  
```powershell
PS C:\Users\sems\Desktop\codepy\os_crypt> python .\lsa_secrets.py --security .\SECURITY --system .\SYSTEM
[*] bootkey : 5484c4f3171a92627a7e00d95ac7d54c
[*] LSA key : db6d52d9ad56df51a2ae3db0a98a3a93fc30932e6fbb9b628c17c96fa909cc87

=== DPAPI_SYSTEM  (44 bytes) ===
   0100000088def18d93157031dd28063c04a7a735efbc1e923af337e1aa410f05c3cb5d1c0a671bb12d2450f7
   version  : 1
   machine  : 88def18d93157031dd28063c04a7a735efbc1e92
   user     : 3af337e1aa410f05c3cb5d1c0a671bb12d2450f7
   -> DPAPI_SYSTEM_HEX = 0100000088def18d93157031dd28063c04a7a735efbc1e923af337e1aa410f05c3cb5d1c0a671bb12d2450f7

=== NL$KM  (64 bytes) ===
   1ee70d0388034200662cbf7f69562d71412b3d72bdae1765ae279be5e1a744769ac5d313bfc000e224b46ab1e7f4bb89da5905c21f146d1b31c294b08b5185c3
```

Burda çok fazla ağız sulandırıcı veri var ama bize şimdilik DPAPI_SYSTEM_HEX yeter. Onu alıyoruz ve stored masterkey file ımızın şifresini şu şekilde çözüyoruz:  
```powershell
PS C:\Users\sems\Desktop\codepy\os_crypt> python .\masterkey.py "C:\WINDOWS\System32\Microsoft\Protect\S-1-5-18\User\bfd9c9bd-04fd-41e8-a8d9-168b8a5f4d95" --dpapi-system 0100000088def18d93157031dd28063c04a7a735efbc1e923af337e1aa410f05c3cb5d1c0a671bb12d2450f7    
[*] opened with: DPAPI_SYSTEM user half                                                                                            
[*] master key : a7d468f1e092a9b268860f4b5ee99151765652a364612d5b348f6ce5e887494b07faed5552e6aff7df80588e41f7e6cc4f09fa9cbfc53b8b5254b35598687d2d
```

İşte bu kadar! Şimdi System kullanıcısının masterkey i ile onun blob unu rahatlıkla çözebiliriz.  
```powershell
PS C:\Users\sems\Desktop\codepy\os_crypt> python .\dpapi_protect.py unprotect --blob 01000000d08c9ddf0115d1118c7a00c04fc297eb01000000bdc9d9bffd04e841a8d9168b8a5f4d95000000000200000000001066000000010000200000001b97fdf3759fd26dfdc179f99c51a98d37a7327278b5f1d4c05db22a3d3f2dc3000000000e80000000020000200000006c2394d7cedd166e0a0644600901672cb9eb885fbd05c20b4fd931e742e133ba1000000002ca6441d5aea2309ee4fad2ab83f810400000002d296c6be1a553e73994a736798a7ac1a2eaa48b0cfb740b9b1bf0a3b8eb54665d943146d890e1d6bece9e94d326d83be149568fe984567ae49d0594c8b813f2 --master-key a7d468f1e092a9b268860f4b5ee99151765652a364612d5b348f6ce5e887494b07faed5552e6aff7df80588e41f7e6cc4f09fa9cbfc53b8b5254b35598687d2d
[*] mac_ok: True  descr: 
[*] plaintext (12 B): 62656e2073697374656d696d
ben sistemim
```

Bunun birde local machine tarafı var. Orda ekstra olarak LOCAL_MACHINE flag ını da vermemiz gerekiyor şifrelerken ve çözerken çünkü LOCAL_MACHINE direkt bilgisayarın kendisini ifade ediyor bir yetki seviyesi yok flag yetiyor. O flag ı gören DPAPI de bu sefer machine sırrı ile veriyi şifreliyor tabii local machine nin masterkey i ile ki oda System masterkeylerinin olduğu dizinin bir arkasında(C:\WINDOWS\System32\Microsoft\Protect\S-1-5-18)  

Bu yazıda DPAPI nin CryptProtect/UnprotectData API lerini elimden geldiğince irdeleyip size anlatmaya çalıştım. Daha çok detay var tabii ama sanırım şimdilik bu kadar yeter. Altta diagramları ve kodları bulabilirsiniz. Selametle kalın.

KODLAR
<https://github.com/SemsYapar/DPAPIScripts>

DİAGRAMLAR  
[cryptprotect_chain](/diags/cryptprotect_chain.html)  
[cryptunprotect_chain](/diags/cryptunprotect_chain.html)  
[masterkey_flow](/diags/masterkey_flow.html)  
[rtl_decrypt_flow](/diags/rtl_decrypt_flow.html)  
[rtl_encrypt_flow](/diags/rtl_encrypt_flow.html)  
