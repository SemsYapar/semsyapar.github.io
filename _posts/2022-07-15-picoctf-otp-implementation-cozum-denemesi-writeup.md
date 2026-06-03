---
layout: post
title: "PicoCTF - OTP Implementation çözüm denemesi (writeup)"
date: 2022-07-15
source: "https://www.turkhackteam.org/konular/picoctf-otp-implementation-cozum-denemesi-writeup.2019904/"
---

Selam herkese bu akşam burda ılık süt tadında bir ctf çözümü yapacağız beraber, hadi başlayalım  
  
MATERYALLER:  
1->herhangi bir C/C++ desteği olan debugger (ben gdb kullanacağım)  
2->herhangi bir programlama dili (ben python kullanacağım)  
3->herhangi bir C/C++ decompiler (ben Ghidra kullanıcağım)  
  
Soruyu tanıyalım:  
Başlık -> OTP Implementation (One Time Pad şifreleme türü demek OTP)  
Açıklama -> Yay reversing! Relevant files: [otp](https://jupiter.challenges.picoctf.org/static/a2a15755ba8be4b4dabf60f8f35ec44e/otp) [flag.txt](https://jupiter.challenges.picoctf.org/static/a2a15755ba8be4b4dabf60f8f35ec44e/flag.txt)  
  
iki adet dosya yüklüyoruz, biri tersine çevireceğimiz uygulama diğeri ise şuan için kullanılamaz halde olan flag  
  
Çözüm:  
elf dosyamızı linux üzerinden yüklediğim dizine geçerek -> ./otp diyip açıyorum, dermişim ne açması, kismeye güvenmek yok, eğitim materyali de olsa işimiz ne bizim değil mi. Sakın he  
elf dosyamızı Ghidra ya yüklüyorum,  
Ghidra bizim için assembly kodunu analiz edicek ve çalıştırılabilir dosyanın entry point'ini (giriş noktasını) bulucak. Ek Açıklama: giriş noktası manuel olarak da bulunabilir, bildiğim kadarıyla çoğunlukla dosyanın sectionları (bölümleri) arasında .text kısmının en başı entry point oluyor  
Ghidra bize entry pointi start function olarak sunuyor:  

![acpxc3k.png](/pictures/tht/acpxc3k.png)

  
gördüğünüz gibi sağ tarafta Decompile kısmıda hemen çalışmış bizim için libc_start_main diye bir fonkisyonun çağrıldıgını içine 4 tane parametre girdiğini görüyoruz.  
gördüğümüz fonksiyon bütün c programlarında bulunan main fonkisyonu yükleyen fonkisyondur içine giren ilk parametrenin main değişkeni olduğunu görebilirsiniz bu değişken main fonksiyonunun nerede başladığını gösteren bir pointerdır aslında.  
Asssembly e bakınca kafanız karışabilir LEA opcode u değer kopyalamak için kullanılır en yaban tabiriyle (fazlaca yaban)  
Fark ediceğiniz ilk şey main değerinin libc_start_main çağrılmadan en son RDI registerına kopyalandığını görmek olur, c kodu halinde ilk parametre olarak gözüküyor assembly de ise en son. Bu tamamen Little endian mevzusu ile alakalı yada ben öyle sanıyorum ama Assembly dünyasında enazından benim öğrendiğim kadarıyla fonksiyonlara parametreler tersten gönderilir. Daha bissürü ters işleri var ama şimdilik bu kadar gıcıklık yeter.  
  

![t7rwqyh.png](/pictures/tht/t7rwqyh.png)

  
main fonksiyonumuzun içine girdik sonunda, sağda decompile halini görebilirsiniz tahmin edeceğiniz gibi param_1 argc, param_2 ise argv[]  
  
şimdi kodun önemli kısımlarını anlamaya çalışalım hem assembly hemde c haline bilgim dahilince değinmeye çalışacağım  

![41t1uya.png](/pictures/tht/41t1uya.png)

  
MOV opcode u da LEA ile hemen hemen aynı, sağdaki değeri soldaki değerin içine yerleştiriyor ayrıntısını bilmiyorum, anlatmıyacağım  
eğer param_1 yani argc 2 den küçükse program key kullanmamızı hatırlatan küçük bir mesaj ile kendini sonlandırıyor eğer büyükse asıl kod çalışıyor  
burda argc yi bilmeyen arkadaşlar için argc bir dosyayı çalıştırırken terminalde onla beraber yolladığımız argümanların sayısıdır.  
bu noktada programın isminin de bir argüman olduğunu unutmalayım yani her türlü param_1 1 olucak ama 1 den büyük olması için çalıştırılırken ekstra bir argüman da gönderilmesi gerekicek bu da anahtar olucak tabiki (Assembly kısmında da JG opcode unu görebilirsiniz "jump if greater" anlamına gelmektedir yani büyükse zıpla nereye zıpla, devamında belirttiği adrese zıpla peki zıplamassa nolur... if in içine girer peki neyle ney karşılaştırılıyor kim kime göre daha büyük? oda JG den hemen önceki CMP yani compare ile kontrol edilir ve burdan çıkan sonuca göre zıplanılıp zıplanmıyacağına karar verilir. Sağdaki değer soldaki değerden çıkarılır sonuç sıfırsa eşittirler eksiliyse ona özel bir flag imzalanır artanlıysa da ona göre, flag mı? diyorsan eğer internetten assembly flags diye aratabilir ve araştırabilirsin)  
  
şimdi else kısmına bakalım programın  

![k7lsndp.png](/pictures/tht/k7lsndp.png)

  
c kodu gayet anlaşılır zaten strncpy fonkisyonu param_2[1] yani argv[1] yani key i alıyor (argv[] de gene C den aşina olmanız gereken argümanların tam halini işaret eden bir pointerdır) ve local_e8 adında bir değere kopyalanıyor en sondaki parametreye bakacak olursak bu kopyalama işlemi 100 byte lık bir kısmı kapsıyor  
assembly kısmında ise direk argv local_108 olarak gösteriliyor zaten dikkatli gözler ilk başta main fonkisyonu ile beraber libc_start_main fonksiyonuna gönderilen paremetrelerin arasında argc ve argv olduğunu anlamıştır, anlamamış olsanız bile sıkıntı yok geri dönün bakın gene anlamıyacaksınız o da problem değil, biraz bireysel araştırma yapmanız lazım. Mevzuyu kafanızda derinleştirmek için şimdilik ben ne söylüyor isem onu doğru kabul edin. Ve gördüğünüz gibi ADD opcode u kullanılmış ve 8 byte eklenmiş argv pointerımıza (register büyüklüğü 64 bit mimari ye ait bir uygulama kullandığımız için 8 byte bu sebeple bir pointer dan diğer pointera gitmek için 8 byte ekleme yapmalıyız index atlamak gibi düşünün aslında zaten alt tarafta olan şey hep budur) ve ikinci argümanı elde ediyoruz  ilki programın adıydı unutmayın.  
ardından iki tane değişken tanımlanıyor ve sıfıra eşitleniyor.  
  

![fevc4wk.png](/pictures/tht/fevc4wk.png)

  
Evet sonunda encryption fonksiyonuna geldik programın burası çok mühim çünkü girdiğimiz key burda şifreleniyor.  
Assembly kısmı baya uzun olduğu için ve zaten burda c kodunu da çok detaylı anlatmıyacağım için burda es geçiyorum dilerseniz kendiniz programı daha sonra detaylı olarak inceliyebilirsiniz.  
while True döngümüz var valid_char fonksiyonu çağırıyor ve daha önceden sıfıra eşitlediğimiz değerlerden birini kullanarak keyimizin ilk indexine yani ilk çarına (char) ulaşıyor (local_e8 argv den gelen key parametremimizdi unutmayın, aslında kendiniz böyle bir ctf i çözerken veya programı incelerken ne olduğunu net anladığınız değişkenlerin üzerine gelip adlarını değiştirebilirsiniz her yerde o isimle anılıcaktır ama ben şimdi kafalar karışmasın diye Ghidra nın belirlediği isimleri değiştirmicem fotoraflar arasında farklılık oluşmasın diye)  
valid_char fonksiyonundan dönen değer eğer sıfırsa döngü bitiyor döngüden çıktıktan sonra aşağıdaki for döngüsünü görebilirsiniz oda keyimizin şifrelenmiş haline her index'ine 'a' ekliyerek (onun byte değerini eklicek her harf in aslında bir sayı olarak ifade edilebildiğini unutmayın mesela küçük a ascii tablosunda hexadecimal sisteme göre 61 e tekabül eder rakamlar bile aslında başka bir sayı olarak ifade edilir)  
for döngüsü ile zaten hali hazırda şifrelenmiş keyimize bide 'a' ekleme işlemi yaptıktan sonra strncmp fonksiyonumuzun içine keyimizi sıcak servis ediyoruz karşılaştırma 100 karakterlik bir karmaşık sayı diziniyle kontrol ediliyor. Heyecanlanmayın bu key değil bu şifrelenmiş keyi kontrol eden zaten doğru keyin şifrelenmiş hali olan bir string dizesi yani doğru key girildiğinde ve şifrelendiğinde ortaya çıkan sonuç bu olmalıymış. Karlıştırmadan dönen dönüş değeri 0 ise bu ikisi aynı demekmiş ve tebrik mesajıyla karşılaşıyoruz eğer dönüt 0 olmazsa "Invalid key!" hatası alıyoruz, işte bu kadar yazımı okdunuz için teşekkür ederim.  
  
Tabiki şaka bu programın altını üstüne getirmeden bugün burdan ayrılmayacağız.  
while döngümüzün içine geri dönelim valid_char dan dönen değer diyorduk diyelimki 0 gelmedi ve while döngümüz durmadı, sırada ne var.  
Sıradaki kontrol index lere erişmek için kullandığımız ve while döngüsünün her sonu geldiğinde bir arttırılan değişkenimizin ilk değerinde yani biraz yukarda tanımlanan değerinde yani 0 olup olmadığını kontrol ediyor eğer sıfırsa ayrı bir muamele değilse ayrı bir muamele ikiside hayra alamet değil gerçi, bu kısmın kullanılan şifreleme algoritmasıyla alakalı olduğunu düşünüyorum. Sonuç olarak bizim korkmamız gereken kısım şifrelenmiş veri değil mi, onun nasıl şifrelendiği eğer şuanki gibi biraz karışıksa bilmek veya vakit ayırmak isteyeceğimiz bir konu değil.  
  
döngümüzde sürekli 2 fonkisyondan değer alınıyor birincisi en başta çağrılan valid_char, ikincisi ise index değişkenimiz sıfır da olsa olmasada çağrılıp dönen değer şifreleme algoritmasında kullanılan jumble fonkisyonu.  

![o92odmp.png](/pictures/tht/o92odmp.png)

  
Baktığımızda bununda abudik gubidik bir şey olduğunu ve karşısında saatlerce oturup düşünmenin, bakışmanın pek iç açıcı olmadığı bir fonkisyon olduğunu görüyoruz.  
Geri dönüyorum.  
  
Şuana kadar döngümüzün key değerimizdeki çarları (harfleri) sırayla index idex dokuduğunu öğrendik ama ne bu işlemin ne kadar gidiceğine dair bir bilgimiz nede ne tür bir işlem olduğuna dair fikrimiz var. Bu sorular ve karın spazmları bizi tek bir yere yönlendiriyor. valid_char fonkisyonu  

![v784syb.png](/pictures/tht/v784syb.png)

  
İsterseniz kodu assembly üzerinden de okumaya çalışabiliriz ama Ghidra nın IDA gibi bağlamsal görsel bir assembly görüntüsü olmadığı için bu jump if lerin arasında kaybolucağımızı düşünüyorum ama gene üzerinde düşünmek istiyenler için daha önce değinmediğim opcode ları şahsıma münazır size açıklamaya çalışayım sonra da decompile kısmına geçelim, olur mu?  
JLE = jump if less or equel (eşitse veya küçükse )  
JUMP = direk zıpla koşul yok  
POP ile PUSH başka bir videonun konusu (ciddli söylüyorum) RET de (return demek, evet şu fonkisyonların sonundakiler gibi, ama daha alangirli)  
  
C kodu kısmında görebileceğimiz gibi içine atılan değerin 0 ila 9 arasında veya 'a' ile 'f' olup olmadığını kontrol ediyor ve eğer öyleyse geriye 1 dönüyor değilse 0 dönüyor.  
Döngümüz üzerine son kez düşünüyoruz.  
  
Demekki dongü bu spesifik alanlar dışında bir değer geldiği anda biticek şekilde tasarlanmış çünkü valid_char 0 döndüğü anda while döngüsü kırılıyor bu spesifik dizinin 100 karakter olduğunu da daha önce öğrenmiştik.  
  
Toparlıyacak olursak:  
Yani program bu aralık arasında bir key oluşturmuş 100 karakter uzunluğunda ve bunu şifreleyip daha önceden şifrelediği bir değerle karşılaştırmasını yapıyor e flag.txt noldu diceksiniz. Böyle ctf lerin rajonu şifreyi bulmaktır sonrasında o doğru şifre sayesinde bayrağı bulursunuz zaten kendileri doğru cevabı verirsek bunu belirtmiş bakın ne yazmışlar:  
puts("You got the keyü congrats! Now xor it with the flag");  
yani flag.txt ile doğru bulduğumuz şifreyi zorlicaz xor ne demek bilmiyorsan internete xor ne demek diyerek araştırabilirsin.  
  
Peki biz böyle bir durumda ne yaparız? Belirl bir aralıkta bulunan sabit bir uzunluğa sahip bir şifre adayını oluşturmak için ne yapmak lazım gelir söyleyin. Teker teker denemek biraz sinir bozucu olabilir, Evet Bruteforce.  
  
python dosyamı oluşturuyorum. dinamik olarak çalıştırılabilir dosyama müdahil etmek için gdb nin python kütüphanesini kullanıcam bu apilerine erişmemizi sağlıyacak  
import gdb yazdım ve düşünüyorum.  
Yapmamız gereken şey 100 harf uzunluğunda kodda belirtilen aralıkta olan keyler oluşturmak ve sonra bunları programın içine atıp şifreleme sonucu oluşan verinin programın içinde gördüğümüz veriyle aynı olup olmadığını kontrol etmek eğer aynıysa oluşturduğumuz key doğrudur ve bunu flag.txt ile zorlıyarak bayrağa ulaşabiliriz. Hadi başlayalım:  

```python
import gdb
bunu_bul = "bajbgfapbcclgoejgpakmdilalpomfdlkngkhaljlcpkjgndlgmpdgmnmepfikanepopbapfkdgleilhkfgilgabldofbcaedgfe"
```

bu programın şifrelenmiş keyimizi kontrol ettiği veri, yukarı bakarsanız görebilirsiniz.  
bulmak isteyeceğimiz sonuç bu olduğu için ismini bunu_bul yaptım.  
  

```python
aralik = ["1","2","3","4","5","6","7","8","9","a","b","c","d","e","f", "0"]
key = ""
```

bruteforce yapıcağımız aralığı belirttik 100 karakteri bunları kullanarak oluşturucaz.  
key i şimdilik boş bıraktım ilerde adım adım doldurucam.  
  

```python
gdb.execute("file ./otp")
gdb.Breakpoint("strncmp@plt")
```

gdb kütüphanem aracılığyla önce bahsi geçen çalıştırılabilir dosyamı açıyorum ardından en son noktada şifrelenmiş keyimin doğru ama şifrelenmiş olan keyle yapıcağı karşılaşmanın gerçekleştiği fonksiyonuma sembol ismi aracılığıyla breakpoint koyuyorum (program debugger tarafından çalıştırılırken tam o noktada karşılaştırma başlamadan önce duracak bu sayede)  
  

```python
for i in range(100):
    for karakter in aralik:
        key_len = len(key)
        gdb.execute("r "+key+(karakter*(100 - key_len)))
        encrypted_key = gdb.execute("x/s $rdi", to_string=True)
        encrypted_key = encrypted_key[17:117]
        if bunu_bul[key_len] == encrypted_key[key_len] or karakter == "0":
            print(encrypted_key)
            key += karakter
            break
       
print(key)
```

programı ilk defa çalıştırma nedenim breakpoint koyabilmekti şimdi onu tekrar tekrar çalıştırıcam ve ne olucak burda bakalım:  
aralik içinden bir karakter seçilicek  
şuan boş olan anahtarımızın uzunlugu yani kaç index olduğu ölçülücek (bir string de her harf bir indextir) şuanlık boş olduğu için ilk seferinde 0 olucak bu değer  
gdb.execute fonkisyonu sayesinde gdb komutu çalıştırıyoruz r/run demek programı çalıştırmak için ama boş boş göndermicez boşluk bırakıp argüman giriyoruz ve keyi ekliyoruz, az önce aralıktan seçtiğimiz karakteri 100 ile key in şuanki uzunluğu çıkarıp çarpıyoruz yani o kadar o karakterden koyuyoruz argümana bu neyi sağlıyor her zaman 100 harf uzunluğunda bir karakter göndericez run ile beraber key uzadıkça çarpım azalıcak denge olucak.  
sonra breakpointse durmuş olduğumuzu hesap ederekn o anki strncmp nin içindeki şifrelenmiş değeri tutan registerımızı tutup onu encrypted_key değişkeninde saklıyoruz (register ne demek bilmiyorsan internete yazıp araştırabilirsin) dönen değerden bize lazım olan yani 100 harflik şifrelenmiş keyimizin olduğu kısmı python un list nimetleri sayesinde kolayca ayıklıyoruz (öbür türlü şuanki komutta verinin bulunduğu adres değeri falanda dönüyor bu ayıklama o yüzden, baş kısmı siliyoruz)  
  
Ve karşılaştırma aşamasında birazdan eğer devam etmesine izin versek programımızın bizim için yapıcağı kontrol aşamasının sentetik ve amacımıza hizmet eden bir kopyasını görüceksiniz. Programımızın içinden aldığımız sonucun o olmasını istediğimiz bunu_bul da sakladığımız şifrenin o anki key_len kaçsa ordaki harfini alıyoruz ve aynısını biraz önce programdan emdiğimiz encrpyted_key imize de yapıyoruz eğer aynılarsa encrpyted key doğru oluşuyor demektir yani aralik'tan çektiğimiz karakter şifrelenince istediğimiz sonuca dönüşmüştür. Bu sebepten onu keye ekliyoruz. ve range(100) e ulaşana kadar yani 100 harfide doğru şekilde yerleştirene kadar döngüye devam ediyoruz.  
  
Anlatınca karmaşık gözüktüğünü biliyorum ama kendi bakış açınızla bakınca daha rahat anlıcaksınız scripti, belki bilmeme ihtimalinizin olduğu gdb apilerini size açıklamam bile yeterliydi sanırım.  
Dosyayı kaydedip gdb -q -x <script_adı.py>  
diyerek çalıştırabilirsiniz  
  
Sonuç olarak for döngüleri tamamen bittiğinde print(key) ile kucağımzıa düşen sonuç doğru key olucaktır isterseniz test edebilirsiniz. Ama işimiz daha bitti mi bitmedi. Daha karpuz kesicez.  
  
Şimdi flag.txt nin içindeki değer ile keyimizi xor lamamız lazım bunu online xor sitelerinden de yapabilirsiniz python ile de yazabilirsiniz tercih sizin xor lama işlemi bitince flagı elde ediceksiniz.  
ben xor işlemi ile birlikte tam kodumu şöyle bırakayım da, lazım olur belki:  

```python
import gdb
bunu_bul = "bajbgfapbcclgoejgpakmdilalpomfdlkngkhaljlcpkjgndlgmpdgmnmepfikanepopbapfkdgleilhkfgilgabldofbcaedgfe"
aralik = ["1","2","3","4","5","6","7","8","9","a","b","c","d","e","f", "0"]
key = ""

gdb.execute("file ./otp")
gdb.Breakpoint("strncmp@plt")

for i in range(100):
    for karakter in aralik:
        key_len = len(key)
        gdb.execute("r "+key+(karakter*(100 - key_len)))
        encrypted_key = gdb.execute("x/s $rdi", to_string=True)
        encrypted_key = encrypted_key[17:117]
        if bunu_bul[key_len] == encrypted_key[key_len] or karakter == "0":
            print(encrypted_key)
            key += karakter
            break
       
print(key)
encrypted_flag = "ffadccb05b5892418ff068dd9d42231e8caf8ebb289ea1873f0a474cabe7ce598db77bac9dfef1d7c2b5af3c35bf5844c082"
for num in range(0, len(key), 2):
    print(chr(int(key[num]+key[num+1], 16)^int(encrypted_flag[num]+encrypted_flag[num+1], 16)), end="")
```

  
Son:  
Evet belki biraz karmaşık gelmiş olabilir enazından banabir kaç writeup okumadan ve saatlerimi vermeden önce öyle gelmişti. Umarım keyif almışsınızdır hiç bir şeyi es geçmeden anlatmaya çalıştım hala sorularınız olursa konuya yazabilirsiniz cevap vermeye çalışırım.  
Kavramları öğrenmek hepsi üzerine ayrı ayrı kafa yormak çok önemli gerçekten...  
Selametle...
