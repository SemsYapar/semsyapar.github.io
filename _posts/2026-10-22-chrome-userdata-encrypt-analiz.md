---
layout: post
title: "Google Chrome User Data Encryption Analizi - Windows"
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

Bu sefer veriyi şifrelerken direkt dpapi cryptprotectdata yı çağırmıyoruz. Onun yerine bir aes 256 key i kullanıyoruz. İşte bu key artık dpapi cryptprotectdata ile User Data altında Local State dosyasında saklanıyor. Kodda göze çarpan bir detay decrypt methodunda, Eğer şifresi çözülecek blob kEncryptionVersionPrefix("v10") ile başlamıyorsa onu gene eski yöntemle yani direkt dpapi kullanarak çözüyoruz. Bu hala cookie çözmek için network servisinin dpapi çağırmasına sebep olacak. Yani aslında sandbox problemi hala çözülmemiş eski verilerin geri çözülebilmesi için bir geriye dönük uyumluluk kodu bırakılmış. Sonraki süreçte eğer issue yorumlarında 19. mesaja bakarsanız cookie db için 2021 yılında bir migration çıktığını göreceksiniz bu başında v10 olmayan tüm verileri çözüp tekrar v10 ile şifreleyip geri kaydeden ek bir kodu içeriyor, buda tüm şifreli verilerin v10 a geçişini hızlandırmak için yapıldı. Günümüzde böyle bir destek yok yani ya v10 ya v20 kullanabiliyoruz. Hangisini kullanacağına Chromium çalışma esnasında karar veriyor. eğer v20 nin yeterlilikleri sağlanıyorsa tercih her zaman v20 yönünde çünkü daha güvenli, öteki türlü güvenli limanımız v10 u kullanıyoruz o her türlü iş yapıyor zaten ama daha az güvensiz.  

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

Gördüğünüz üzere tek fark entropy2 nin gelmesi o da duruma bağlı prompt dan geliyor yukarda söylediğim gibi. Peki bu fonksiyon ne yapıyor, dpapi.dll de tanımlı bu fonksiyon esas işlevi yerine getirecek olan dpapisrv.dll ile iletişim kurup rpc üzerinden şifrelenecek veriyi LSASS(Local Security Authority Subsystem Service) e aktarma görevini üstleniyor. Burda lsass ne buna girmicem ama Windows un kritik process lerinden biri olduğunu çok sıkı korunduğunu ve temel amacının bilgisayarınızdaki lokal oturum işlemlerini doğrulamak ve yönetmek olduğunu söyleyebilirim. Peki neden lsass katına çıktık. Çıktık evet çünkü lsass hassas bilgiler içeren bir process, kullanıcı masterkey leri gibi... Bizim masterkey ile işimiz var birader çünkü amacımız en baştan beri belirttiğimiz gibi sadece kullanıcının kendinin şifresini çözebildiği bir şifreleme hizmeti vermek. Masterkey lerde bunun için var. Şuan açıp bakabilirsiniz %APPDATA%\Microsoft\Protect dizini altında kullanıcı SID inizin olduğu dosyada masterkey leriniz bulunur bunları görmek için tabii explorer da sistem dosyalarını gör ayarını yapmanız lazım. Bu dosyalarda masterkey leriniz şifreli olarak tutulur ve bu şifrenin anahtarı da sizin kullanıcı parolanızdır. Tabii çok değişken durumlar var MSA ile oturum açmış olabilirsiniz, PIN ile oturum açmış olabilirsiniz, bir domain ağındaki bir kullanıcı olabilirsiniz biz bu seçenekleri şimdilik kapatalım. Local bir kullanıcı hesabınızın olduğu en basit senaryoyu konuşalım.  

CryptProtectDataNoUI RPC ile ncalrpc:protected_storage e bağlanır bu lsass process inde çalışan dpapisrv.dll in dinlediği hattır. Sonra sırayla SystemFunction040 ve NdrClientCall3 fonksiyonlarını çalıştırır. NdrClientCall3 şifrelenecek veriyi dpapisrv nin ilgili interface inin hedef fonksiyonunu(operation number ile seçerek) gönderir ve cevabı dpapisrv den bekler. Ondan önce SystemFunction040 diye gözüken ama esas adı RtlEncryptMemory olan fonksiyon ise yola çıkacak plaintext imizi yani şifrelenecek verimizi yol için şifreler, bu şifreleme o oturum için bir şifrelemedir. RtlEncryptMemory veriyi şifrelemek için kernel deki ksecdd(Kernel Security Support Provider Interface) e gider gider, ksecdd de abisine yani CNG.sys(Cryptographic Next Generation) driver a gider. CNG her boot timeda rastgele oluşturulan anahtarları veriyi şifrelemek için kullanır.   
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
veri 8 er byte a bölünecek şekilde zaten SystemFunction040/RtlEncryptMemory e girmeden önce padding edilmişti. CNG şifrelenecek veri boyutu eğer 16 nın katı ise AES-256-CBC, 8 in katı ise 3DES kullanır. Bu detayları sizi çok sevdiğim için veriyorum bu arada.  
Mekanizmanın nasıl çalıştığını kendi gözlerinizle görmek istiyorsanız RtlEncrypt/DecryptMemory fonksiyonlarının bu macerasını python kodu ile simüle ettiğim aşağıdaki kod ile oynayabilirsiniz. Tabii sisteminizdeki gerçek şifreli verileri çözmek için kernel memory nizden Yukardaki kodda gördüğünüz 3 SystemPrng çıktısını almanız lazım. WinDbg ile yapabilirsiniz. 
<details markdown="1"> 
<summary>cng_encdec_memory.py</summary>
```python
{% include_relative kods/cng_encdec_memory.py %}
```
</details>  

O yüzden şifrelenen veri bilgisayar kapatılıp açılınca artık geri çevrilemez. Kısa vaadeli şifrelemeler için kullanılır. Burda amacımız RPC verisini güvenli şekilde taşımak olduğu için kullanımı anlamlıdır. 4 adet şifreleme modu vardır. Bunlar: Same Process, Cross Process, Same Logon ve System dir.  
Same Process modu veriyi api yi çağıran process in kimliğinide kullanarak şifreler böylece sadece o process bu şifreyi çözebilir olur.  
Cross Process veriyi şifrelerken ekstra anahtar kullanmaz o yüzden herkes çözebilir olur.  
Same Logon veriyi Logon LUID ile şifreler böylece o oturumdaki o kullanıcını yetkisi ile çalışan process ler şifreyi çözebilir.  
System ise adından da anlaşılacağı gibi veriyi sadece System kullanıcısının deşifre edebilmesini sağlar bunun için veriyi çözerken çözmek isteyen yani api yi çağıran process in token ine bakar. System token i değilse veriyi çözmez.  

İyi anlatabildiysem bizim durumumuzda hangi şifreleme yöntemini kullanmamız daha doğru tahmin edebiliyor olmanız gerekiyor. Aslında gerekmiyor:D çünkü tatlı bir trick var. Cross Process en mantıklısı gibi gelecektir ama Same Logon kullanılıyor. Nasıl Same Logon lsass nasıl çözecek veriyi System kullanıcısı o dediğinizi duyar gibiyim. Olay şu ki. dpapisrv.dll içinde rpc çağrısını yapan process in token ine RpcImpersonateClient api si ile bürünüp öyle RtlDecryptMemory ile şifreli veriyi çözer. Sonrada bu veriyi masterkey ile şifreleyip geri isteyen process e iletir.  

Burda algılayışınızı netleştirmek için claude ile özene bezene hazırladığım birkaç diagramı sizle paylaşmayı uygun gördüm. Yazımın bu noktasına kadar değindiğim genel CryptProtect/UnprotectData zincirini ve bu zincirde spesifik olarak geçiş(transit) aşamasında kullanılan SystemFunction40 ve 41 i yani RtlEncDec fonksiyonlarını kernel akışları ile beraber gösteren diagramlar olacak bunlar.  

<iframe src="/diags/rtl_encrypt_flow.html" width="100%" height="500px" style="border:none;"></iframe>
<iframe src="/diags/rtl_decrypt_flow.html" width="100%" height="500px" style="border:none;"></iframe>