---
layout: post
title: "Şöylemesine bir Tersine Mühendislik"
date: 2023-06-19
source: "https://www.turkhackteam.org/konular/soylemesine-bir-tersine-muhendislik.2041716/"
---

Selam millet bu konuda tersine mühendislik hakkında genel tanımlamlar, tarifler anlatıcam amacım konuyla ilgili bakış açınızı genişletmek. Saldırı Timleri gururla sunar:  
  
Öncelikle kendimi tanıtıyım çıtırından. Ben şahsen hep bilgisayarın çalışma mekaniklerine dair bir şeyler öğrenmek isteyen birisi olarak tanımladım kendimi bu yolda beni en derin yolculuğa çıkaran alan güvenlik oldu. Bu şekilde de bir nevi ne ile uğraşıcağımı bulmuş oldum. Tersine mühendislik ise bu noktada keşfettiğim ve benimsediğim bir alan oldu. Foruma ilk kayıt olduğum zamanlarda tek tek tüm kategorilere ve isimlerine baktığımı hatırlıyorum. Tersine mühendislik kavramı daha o zamanlarda bana ilginç, havalı ve gizemli geliyordu. Öğrenmek istiyordum ama bunun için bir temel e ihtiyacım olduğunun da farkındaydım. Yıllar geçti ve şuan bu açlığımı gidermeye yeni yeni başlıyorum. Programların yazılması, bunların bilgisayarın anlayacağı bir formata dönüştürülmesi, işletim sisteminin bu akışı düzenlemesi ve işlemcimin mantıksal kapılarından süzülen elektriğin pixellerle gözümüzde mana bulması...  
  
Tüm bu süreç bilgisayarlar hayatımıza girdiğinden beridir istesekte istemesekte şundan bundan duyduğumuz ve aslında nasıl olduğunu bilmediğimiz teknik bilgileri içeriyor. Peki bu niye bizim umrumuzda olmalı? Kodu yazalım ve adından ne yaptığı belli olan fonksiyonları ard arda sıralayarak istediğimiz algoritmaların çalışmasını izleyelim, pekala buna saygı duyarım, herkes sektörde sürecin bir tarafında kafa patlatmakla meşgül. Pentesterlar javascript e ve network protokollerine hakimken yazılımcılar modern kod bloklarını üst üste koyuyor. Oyun yazılımcıları ise sadece kafalarındaki düşünceyi gerçekleştirme derdinde. Her şeyin öncesinde ne var peki?  
Tüm bunların anlam bulduğu nokta neresi? Klavyede bastığımız tuşlar nereye gidiyor? wifi adaptörleri nasıl çalışıyor? Oyunlar hangi levelde olduğumuzu nasıl hatırlıyor? Python nasıl çalışıyor? Derleme işlemi nasıl gerçekleşiyor? Programlar şifremizin yanlış olduğunu hangi yolla teyit ediyor? HTML kablosu görüntüyü nasıl aktarıyor yada görüntü monitörde ne şekilde oluşuyor? İşlemci CSGO oynamamızı nasıl sağlıyor? İşletim sistemlerinin işlevi ne? Bir programa çift tıkladığımızda onu çalıştıran mekanizmanın arkasında ne var? Bilgisayara dair her şeyi bilirsek neler yaparız neler düşünsenize! Ben bunun peşindeyim.  

<iframe width="560" height="315" src="https://www.youtube.com/embed/CsSeKl7pdvk" frameborder="0" allowfullscreen></iframe>

  
Herkes sürekli windows defender ı nasıl geçerim. FUD rat nasıl yaparım. DDOS nasıl atarım. Sitelere index nasıl basarım diye söyleniyor. Tabi bunları yapabilmek kötü değil kendimizi bunlarla sınırlıyorsak kötü. Öğrenilecek çok şey var, keşfedilecek bissürü protokol var. HTTP, FTP, Handshake ler, SSL/TLS, IP, TCP, UDP bunlara kimsenin vakıf olamadığından daha vakıf olduğunuzu düşünsenize kim bilir kafanıza yapacak nasıl deli deli şeyler gelir. Ama bir çoğumuz taklitten öteye gitmeyecek şeylerle uğraşıyoruz. Bilgi sınırımızı genişletmek yerine hazır gıda gibi hazır bilgi peşindeyiz.  
Kimsenin bir şey bildiği yok! Bİr arayıştır tersine mühendislik, sorgulama, anlama derdine düşmektir. Yetinmemektir. Bir manifesto nuz varsa oda bu olsun millet.  
  
Şimdi bizim bazı terimlerimiz var amatör sektörde gelin bunları biraz tanıyalım yeterince felsefe yaptık:  
  
**Obfuscate (Karmaşıklaştırmak):**  
Benim en çok gördüğüm olaydır. Biz Tersine Mühendisler en çok anlayamadığımız koddan nefret ederiz bünye kaldırmaz. Onu içimizde hissetmek isteriz. Eğer bunu sıkıcı buluyorsanız bu işe hiç girişmeyin.  
a = 2+2
print(a)  
############################################################  
a = (2 + 2 - 1) * ((3 // (1 ** 2) % 5) + ((10 // 2) & 3 | 8) ^ 2) - (2 * 19)
print(a)  
Bu iki python kodu aslında aynı şeyi yapıyor ama biri diğerinden "daha zor" okunuyor. Tabi bizim obfuscated(karmaşık) olarak tanımladığımız bu durum bilgisayar için sadece daha fazla elektrik demek nede olsa onun anlamak gibi bir derdi yok Kapiş.  
  
**Encrypt/Decrypt Mekanizmaları:**  
Çoğu kez zararlı yazılım yazanlar işlevlerinde kullanacakları verileri bünyelerinde şifreli olarak tutar ve bunları gerekli zamanda çözüp o şekilde kullanırlar bu hassas(C&C server ip, anahtarlar, erişilmek istenen yollar, çalıştırılmak istenen kodlar gibi) verileri.  
  

```python
def icine_ne_girdigi_hemencicik_belli_olan_fonksiyon(a):
    if (a == b"cokgizli"):
        print("Şimdi puşluk yapabilirim")
 
text= b"cokgizli"
a = text
icine_ne_girdigi_hemencicik_belli_olan_fonksiyon(a)
```

  

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def icine_ne_girdigi_hemencicik_belli_olmayan_fonksiyon(a):
    if (a == b"cokgizli"):
        print("Şimdi puşluk yapabilirim")

key = b'keyetakilmaaesbu'
cipher = AES.new(key, AES.MODE_ECB)
text= cipher.decrypt(b'oT\xb8\x07\xf5\xce\x7f\xc7\x1d)\xc3\x0c\xf1\xa7\xd5\x9f')
a = unpad(text, 16)

icine_ne_girdigi_hemencicik_belli_olmayan_fonksiyon(a)
```

  
Gördüğünüz gibi ilk kodda veri şifrelenmeden programın içinde statik bir şekilde tutuluyor bu hem çalışma esnasında hemde programı çalıştırmadan o veriyi görebileceğimiz anlamına geliyor ki bazı insanlar ikinci yolu daha güvenli buluyor (işi bilen için öyle olmasada)  
  
**Compile/Decompile ve Machine Code/Assembly:**  
Biraz daha teknik kısımlara geçelim. C ile bir program yazdınız diyelim. Derleme tuşuna basarsınız ve programınız artık çalışabilir hale gelir bir exe elde edersiniz (Windows ortamı için konuşuyorum Linux da da bir elf executable olur bu) Peki bu hangi formdur artık? Evet makine dili derler dimi peki nedir makine dili? Açıkçası bunu bende çok bilmiyorum ama tek bildiğim makine dilinin işlemcinin anladığı tek format olduğu bu formatın derleyiciler tarafından oluşturulduğu ve işlemci mimarisine özel olarak hazırlandığı, bu oluşan dosyalara da çalıştırılabilir dosyalar dememiz. Makine dilini kimse okumaz. Bunu bir tık üst seviyeye çıkarıp bizim için daha anlamlı bir hale getirmeye çalışırız. 01 ler den daha anlamlı yani... Ve assembly dili dediğimiz ara dil katmanı ortaya çıkar. Burda işlemcinin yapmak istediği şeyleri semboller kullanarak ifade ederiz. Basit bir örnek veriyim.  

![64x5360.png](/pictures/tht/64x5360.png)

  
soldaki ikilik tabanın hexadecimal dökümü... Bir exe dosyasının içindeki verinin hexa sayı sistemindeki görüntüsü sağda ise bunun assembly karşılığı... mesela movl ile soldaki hex sayısını eax register ına verirsiniz. Değişken atamak gibi düşünün.  
C kodunuzun makine diline çevrilmesi serüvenine compile(derleme) denir. Decompile ise tahmin edeceğiniz gibi bu süreci geri dönüştürmeye çalışmaktır. C gibi low level dillerde geri dönüşüm daha zordur çünkü bu diller yüksek performans ı hedefler bunun için bilgisayarı ilgilendirmeyen değişken ve fonksiyon isimlerini silip adres değerlerini kullanırlar. Kodu ellerinden geldiğince optimize etmek için kodu ilk halinden daha farklı bir mantıksal düzlemde oluşturabilirler. Buda orjinal yazar kodunu elde edebilmenizi imkansız hale getirir. Genede assembly görüntüsüne mecbur olmassınız. IDA Pro, Ghidra gibi decompiler araçları sayesinde kodu "olabildiğince c" haline dönüştürebilirsiniz.  
  
Biz süreci kafamızda şu şekilde aşamalandırırız: Compile > Exe. Exe > Dissassembly işlemi > Assembly kodu > Decompile işlemi > ilk haline benzemesede oldukça low olsada bir c kodu (source)  
Tabi modern dillerde kodu neredeyse ilk haline çevirebiliyoruz. C# gibi.  
  
  
**Derlenen ve Yorumlanan Diller - Scriptler :**  
Tabiki her dil C gibi derlenip exe si çalıştılacak diye bir şey yok. Bazı diller sadece çalıştırıldıkları an dönüştürülüp işlemcinin anlayacağı makine dilini çevrilirler. En popüler örnekleri javascript ve python, php gibi script dilleri olarak adlandırılan dillerdir.  
Python esasen bir C uygulamasıdır.  [GitHub - python/cpython: The Python programming language](https://github.com/python/cpython) adresinden python un kaynak kodlarını sürüm sürüm görebilirsiniz. Görebileceğiniz üzere c ile yazılmış bir uygulama aslında peki biz buna neden dil diyoruz? Öyle bir uygulama ki içine kendi kuralları bütününde yazdığınız şeyleri anlamlandırarak onları çalıştırıyor. Bu süreci python yönetiyor. Siz python un istediği gibi yazıyorsunuz oda bunu bildiği gibi çalıştırıyor. Aslında bu mantıkla düşünürsek İşlemcide bir uygulama diyebiliriz bir algoritmaya tabi nede olsa ve ona verdiğimiz makine dilini dilim dilim okuyup anlam bulduğu şekliyle çalıştırıyor.  
Python üzerine biraz daha konuşalım. Python kodunuzu yazdınız ve çalıştırdığınız "python dosyaadi" diyerek mesela, bu noktada python.exe ye programınızın yolunu vermiş oldunuz şimdi python.exe o dosyayı okuyup onu derleyecek. Evet yanlış duymadınız derleyecek ama bu C dilinin derlenip makine diline dönüşmesi gibi low bir derleme değil. Python sadece kodu birazdan çalıştıracağı formata dönüştürmeye çalışıyor. Biz buna bytecode diyoruz. Aynısını java da da görebiliriz bu ara format şu işe yarıyor. Bizim yazdığımız kod optimize edilerek hem boyutu küçültülüyor hemde hataları ayıklanma şansı bulunuluyor eğer bariz bir hata yapmışsak bunu programı çalıştırmadan fark etme imkanı buluyoruz zaten sadece derlenen (C gibi) dillerin en önemli avantajlarından biri budur yani derleme esnasında programın hatalarını görebilmek böylece çalıştırma esnasında sürprizlerle daha az karşılaşırız. Bu sayede bu ara evreye sahip diller Derlenen dillerin avantajını bir nevi kullanmış oluyorlar mı eveeet. Peki sonra? Aynı zamanda bu bytecode objesi python kurulu herhangi bir bilgisayara yüklenip kolayca çalıştırılabiliyor (belirli limitasyonlar var tabi) böylece crossplatform bir hale gelmiş oluyor yazdığımız kod bu olayın en önemli temsilcisi java dır. Bu sayede yorumlanan dillerin avantajını kullanmış oluyorlar yani iki tarafında iyi özelliklerini bünyelerine topluyorlar diyebiliriz  
  
**Zararlı Yazılım Analizi Hakkında:**  
Birazda malware ler hakkında konuşalım. Bu arkadaşlar hepimizin hayatımızın bir evresinde muhakkak sorunu olmuştur. Birileri bunları yazıyor ve internete salıyor peki onları anlamak bizim için neden önemli:  
* Bikere bu bir güvenlik problemi ve eğer alanımız güvenlikse bu arkadaşlardan nasıl korunucağımızı ve onlarla nasıl başa çıkıcağımızı bilmek bizim için önemli.  
* Aynı zamanda kullandıkları teknkikleri, metotları ve taktikleri inceleyerek atak vektörleri konusunda fikir sahibi olup tecrübe kazanarak kendi malwar... Kestik Tecrübe kazanarak bilgisayar bilgimize bilgi katabilir ve tatmin olabiliriz.  
* Keza bence bu adamların yaptıkları özellikle şu modern virüsleri incelemek onları saklandıkları kabuklarından çıkarıp ne yapmaya çalıştıklarını anlamak gerçekten çok zevkli bir faaliyet programlama ve algoritma yönünden de bizi geliştirdiği kesin basitçe kod analizi yaptığınızı düşünün code review diyorlar ya ondan işte  
  
Size bu noktada keşfettiğim bazı adamları tavsiye edebilirim:  
[https://www.youtube.com/@OALABS](https://www.youtube.com/@OALABS)  
[https://www.youtube.com/@MalwareAnalysisForHedgehogs](https://www.youtube.com/@MalwareAnalysisForHedgehogs)  
sanırsam kankiler zaten. Ben bu arkadaşlardan çok şey öğrendim ve bunlar sayesinde kendi mini analizlerimi de yapabiliyorum online sandboxlardan ilgimi çeken virüsleri indiriyorum ve analiz ediyorum.  
  
  
**Unpack, Dump etmek:**  
Şimdi bunlar biraz barzo kavramlar farkındayım ama ben dahil pek çoğumuz bunlara aşinayız detaya inince bu kadar basit bir ayrıma sahip olmadıklarını anlıyorsunuz ama şimdilik yüzeysel olarak tanımaktan zarar gelmeyeceğini düşünüyorum.  
Şimdi Unpack etmek çoğunlukla şöyle oluyor zip nedir biliyorsunuzdur değil mi Hani WinRAR a atarsın extract dersin içindeki veriyi alırsın hani sıkıştırılmıştır o veri falan işte aslında bunu exe ler içinde yapıyorlar yani exeyi sıkıştırıp onu çalışma zamanında decompress(sıkıştırmanın tersi) edip içindeki veriyi çalıştırarak bu bağlamda kullanımlar için var olan bazı araçlar var. Ama çoğu insanın istediği şey genelde kodunun okunmasını engellemeye çalışmak oluyor. E tabi amatörleri uzak tutuyor bu yöntem ama sonuç itibariyle veri nerde decompress ediliyorsa orda onu yakalayıp. Okuyabiliriz değil mi? Çok "güvenlikli" bir yöntem değil. D  
Dump etmek de tabi bakarsan binlerce manada kullanılabilir ama benim en çok gördüğüm. RAM de o an çalıştırılmakta olan uygulamanın RAM den sökülüp diske yazılması olayına deniyor. Bununda kullanılmasının sebebi şu oluyor. Kendini bir şekilde decompress eden yada ne bileyim asıl uygulamayı içinde şifreli bir şekilde tutup zamanı gelince bunu çalışma esnasında çözerek ikinci bir process olarak başlatan ve kendisini kapatan bir uygulama düşünün bu noktada siz RAM de çalışır olarak bulduğunuz uygulama decompress edilmiş, şifresi çözülmüş, saklanmak istenen asıl uygulama oluyor anladınız mı. Sizde onu RAM den söküp diske kaydediyorsunuz bu sayede manuel olarak data nasıl şifrelenmiş nasıl çözülmüş falan fistan uğraşmadan kökten meseleyi çözüp asıl istediğiniz uygulamanın kaynak kodlarını (makine dilinde tabi) cukkalamış oluyorsunuz.  
  
**Protector lar:**  
[DIE](https://github.com/horsicq/Detect-It-Easy)gibi size çalıştırılabilir dosyaya dair bir takım ön bilgiler veren programlarda görebileceğiniz bi anahtar kelimedir "protector" bu, programızda bilindik bir koruma programı yürürlükteyse gördüğünüz bir mesajdır. Bu tarz bilindik ve popüler korumalar exe de belirgin izler bırakırlar DIE gibi araçlarda bu izleri tespit edip hangisinin neye tekabül ettiğini fark edecek mekanizmalara sahiptirler. Mesela programınızın [ConfuserEx](https://yck1509.github.io/ConfuserEx/)ile korunduğunu gördünüz. Bu noktada confuserex in tam olarak neler yaparak programı koruduğunu bilmeniz işinize yarayabilir. Ve bunları aza indirmenin ve kodunuzu obfuscate, pack gibi işlemlerden temizlemenin yollarını arayabilirsiniz. Kolayca internetten aynı confuserex kadar popüler bir deobfuscator olan [de4dot](https://github.com/de4dot/de4dot)u indirip şansınızı deneyebilirsiniz. Onunda yaptığı sonuç olarak confuserex i tespit ettikten sonra protector un yaptığını tahmin ettiği kargaşayı toparlamaya çalışmak olacaktır. Tabi algoritmik şekilde.  
  
**Virtualization Protect:**  
Bu işlem obfuscate olayına yeni bir soluk getiriyor yani çok da derinlemesine bilmediğim bir konu ama kısaca kodu assembly talimatlarına kadar obfuscate ederek artık orjinal halini manuel olarak ortaya çıkarmanızı teknik olarak imkansız hale getiren de4dot gibi tool ların işe yaramadığı bir noktada kodu bozan bir yöntem diyebilirim. Daha da sıkmıyım.  
  
**Program lisanslarını kırmak hakkında:**  
Bazı programlar içlerinde tuttukları şifreyi size sorar bunun girdinizle aynı olup olmadığını kontrol eder. Bazıları server larına istek yollar ve database lerinden anahtar - kullanıcı adı eşleşmesi yaparlar. Bazıları hwid, ip adres gibi uniq olabilecek bilgilerinizi kullanarak bilgisayarınızı tespit etmeye çalışırlar. Onlar istedikleri kadar çalışsınlar Siz mekanizmayı çözdükten sonra bu süreci istediğiniz gibi manipüle edebilirsiniz.  
İster kaynak kodda değiştirmeniz gereken yeri tespit edip bir byte la işi bitirirsiniz:  

```python
a = input("Şifreni gir: ")
if a == "harbisifre":
    print("Merhaba")
```

```python
a = input("Şifreni gir: ")
if a != "harbisifre":
    print("Merhaba")
```

  
İsterde programın iletişim kurup lisans kontrolü yapmaya çalıştığı server ın ip adreslerini local ağınızda var edip (bir takım hosts manipülasyonları ile) programın sizin localhost unuzda sizin kontrolünüzdeki server dan lisans ı kontrol etmesini istemesini sağlayabilirsiniz bu noktada yapacağınız tek şey "evet bu kullanıcı database imde var" mesajını programa cevap olarak dönmek olur  
Tabi bu işlerin bissürü inciği cinciği var ama zaten amacımız oralara girmek değil şimdilik. Kafanızda bir fikir oluşturmak gayemiz.  
  
**Statik ve Dinamik Analiz:**  
Statik adı üstünde kod tatlı tatlı duruyorken onu incelemek stringlerine bakmak algoritmasını çözümlemek kullandığı kütüphane ve metodları gözlemlemektir ve ön bilgi toplamamızı, gerekirse dinamik analiz için hazır olmamızı sağlar.  
Dinamik analiz ise kodu akıştayken incelemektir yani çalışırken bunuda en sevdiğimiz programlar olan debugger larla yaparız debugger lar için ayrı bir konu açmayacağım kısaca programı adım adım çalıştırmamıza istediğimiz değişkenine anlık olarak müdahale etmemize istediğimiz yerde programı durdurmamıza yarayan uygulamalardır. Bunları kullanarak dinamik analiz yaparız. Tabi yerine göre özelleşmiş bazı tool larında dinamik analiz yapabileceğini söyleyebiliriz, mesela bir unpack toolu sizin elinizi kirletmeden uygulamayı hızlıca çalıştırıp gerekli yerde onu durdurup veriyi çekebilir. Bunun gibi kodun çalışmasından faydalandığımız her analiz anı bizim için dinamik analizdir en önemli faydası bir fonksiyonun ne yaptığını tam olarak anlamaya gerek kalmadan sonucu görmemizi sağlamaktır.  
Şuraya en sevdiğim statik analiz aracını ve debugger ını bırakayım: [Hex Rays - State-of-the-art binary code analysis solutions](https://hex-rays.com/ida-pro/)  
  
**Windows API/Win32:**  
Tek başına ele alınması gerekicek kadar önemli bir konu tamam windows la aranız olmayabilir ama tersine mühendislikle ilgilenecekseniz muhakkak windows api lerinin bazılarını tanımanız ve nasıl çalıştıklarını bilmeniz elzemdir. VirtualAlloc, VirtualProtect, WriteFile, CreateProcess, ThreadStart CrpytoAPI aklıma gelenlerden sadece bazıları. Bunları bilmek en çok zararlı yazılım analizinde işinize yaramakla beraber oyun hileleri gibi kodlarını kimsenin görmemesini istedikleri uygulamalarda da yoğun olarak kullanılan apiler oluyor. Adlarını bilmeniz yetmez argümanlarını, çıktılarını, hata mesajlarını bilmeniz ve bunu debugger üzerinde nasıl göreceğinizi anlamanız lazım. Windows un genel yapısında neredeyse her iş için api ler kullanılır. API ler user katmanından kernel katmanına komut göndermemize yarar. Windows bu şekilde kendisini yönetmemize izin veriyor. E bizde şimdilik onun suyundan gideceğiz.  

![k5pvmhp.png](/pictures/tht/k5pvmhp.png)

  
  
**KAPANIŞ:**  
Düşünsem aklıma başka kavramlarda gelir sanırım ama bu haliyle bizimkileri yeterince tatmin ettiğimi düşünüyorum. Umarım kafaları açmıştır bu yazım. Aklıma geldikçe kavramlar eklemeler yaparım. Sorularınız varsa burdan sorabilirsiniz. Biliyorsam ve uygunsam cevaplarım.  
Tersine mühendislik hem fikren hemde faaliyetleri babında çok geniş ve derin bir alan herkesi burda görmek isterim. Ama sakın onu bunu taklit etmeyin kafanıza vururum. Araştırma yapın sistem öğrenin. Tersine mühendis dediğin sistem çözer sistem oluşturur. Yazılımcılardan tek farkımız olaya amuda bakabilmemizdir belki. Yada herkesten... Saldırı Timleri Sundu.  

<iframe width="560" height="315" src="https://www.youtube.com/embed/O8mGkct3oys" frameborder="0" allowfullscreen></iframe>

  
Selametle kalın.
