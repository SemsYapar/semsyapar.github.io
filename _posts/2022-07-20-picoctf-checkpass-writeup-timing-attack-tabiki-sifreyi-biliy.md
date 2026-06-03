---
layout: post
title: "PicoCTF - Checkpass (writeup) | Timing Attack | tabiki şifreyi biliyorum, ilk karakterini bi hatırlasam..."
date: 2022-07-20
source: "https://www.turkhackteam.org/konular/picoctf-checkpass-writeup-timing-attack-tabiki-sifreyi-biliyorum-ilk-karakterini-bi-hatirlasam.2020228/"
---

Selam herkese, kurabiyelerinizi alıp buraya gelin çünkü ılık süt tadında bir CTF çözümü daha yapacağız.  
  
AÇIKLAMA:  
What is the password? File: [checkpass](https://mercury.picoctf.net/static/2d896be679ee8c9650fb7433296ad7b1/checkpass) Flag format: picoCTF{...}  
  
Klasik, açıklama yapmama gerek yok, verdiği dosyanın şifresini bize soruyor.  
  
GİRİŞ:  
Ben bu çözümü şu: 

<iframe width="560" height="315" src="https://www.youtube.com/embed/HPmAzLMkENk" frameborder="0" allowfullscreen></iframe>

 youtube videosundan ilham alarak yaptım başka çözüm yollarıda var araştırırsanız CTF i ismiyle bulabilirsiniz. En makul olanı bu, en zevklisi de...  
  
Değinmeden geçemiyeceğim:  
1. Sizden isteğim gene aynı, nütfen eline sağlık tarzında mesajlar atarak konumu boğmayın, bana iyi dileklerinizi konu ile ilgili soru sorarak ve tartışarak iletebilirsiniz.  
2. Aaa evet bu CTF i başkalarıda çözmüş, ne kadar ilginç, vay be demek CTF i daha öncesinde çözenlerin videolarını ve makalelerini okuyup edindiğim bilgileri çözümümde kullandığımı şıp diye anladın. Çok zeki olduğunu bilmeni isterim nasılda yakaladın beni, oysa ben bütün forumu bu CTF i tek benim çözdüğüme inandırmaya çalışıcaktım millete artislik yapıcaktım, sen, sherlock, olayı hemen çözdün. Bravo.  
  
TEST:  
Programı çalıştıralım bakalım ne yapıyor.  
./checkpass  
Usage:  
        ./checkpass <password>  
Bu şekilde bir çıktı verdi bizden argüman istiyor.  
  
./checkpass 12345  
Invalid length  
  
Uzunluk yanlış diyor isterseniz arttıra arttıra yada eksilte eksilte deneyin ama bunu denemek sıkıcı bence, gerekli ön bilgiyi topladık şimdi içeri dalma zamanı, Jax ın da dediği gibi "Hadi dalalım"  
  
ÇÖZÜM:  
Dosyamız elf executable, linux ortamında çalışan çalıştırılabilir bir dosya anlıyacağınız ama bu onu windows üzerinde IDA da incelememe engel değil. Dosyaya yakından bakalım.  
Dosya oldukça karmaşık gözüktüğünden string araması yapmak bana pek makul geldi böylece can alıcı yerlere gidebiliriz.  
![cddri3z.jpg](/pictures/tht/cddri3z.jpg)  
  
Gördüğünüz gibi dikkatimi invalid lenght ve invalid password diye iki tane string çekti şimdi üzerlerine basıp nerde tutulduklarını görebiliriz, ben ilk olarak invalid lenght e tıklıyacağım invalid password da fazla uzağında değildir zaten.  
![lcsfqvj.jpg](/pictures/tht/lcsfqvj.jpg)  
  
IDA kendisi isimlendirmiş offset değerini içindeki password kelimesinden dolayı, sağ tıklayıp "list cross reference too" ya basarak bu offsetin nerelerde kullanıldığını görebilirsiniz. Ben ilkine tıkladım.  
Zaten bir tane varmış sadece şimdi fark ettim.D Bir de ne görelim bu offsetimizin de başka bir offset tarafından tutulduğunu görüyoruz iç içe pointer gibi şimdi ona da sağ tıklayıp referanslarını görelim bakalım.  
Gene bir yer bulduk, basalım. Bir fonkisyonun içerisinde rax register ına atanmak için kullanıldığını görebilirsiniz.  
![hl88cq9.jpg](/pictures/tht/hl88cq9.jpg)  
  
Biraz komik kaçıcak ama şimdi de bu fonksiyonun nerde kullanıldığını araştırmamız lazım çünkü gördüğüm kadarıyla bu fonksiyon kendi içerisinde bir şey kontrol etmiyor daha çok sonuç gibi gözüküyor.  
fonksiyona sağ tık yapıp referanslarına bakalım şimdi, iki yerde kullanılmış. Birincisini seçiyorum.  
![7cbqdj4.jpg](/pictures/tht/7cbqdj4.jpg)  
  
Tahmin ettiğim gibi, bu fonksiyon bir kontrol mekanizmasının sonunda çağrılıyor gibi duruyor, sol altta görebileceğiniz gibi graph overview bizim içinde bulunduğumuz fonkisyon havuzunu gösteriyor amma büyük ve aşağılara kadar iniyor, korkutucu...  
Ama biz önümüze bakalım, karşımızda rax+28h ın tuttuğu değeri 29h ile karşılaştıran cmp opcode u var. cmp karşılaştırma yaparken kullanılır iki değişkeni alır ikincisini birincisinden çıkarır sonuç sıfırsa zero, değilse ise pozitif veya negatif olmasına bağlı olarak farklı flagler yükseltir bu durumda eşit olup olmadığına bakıyor çünkü bir aşağısındaki jnz opcode u tam olarak bunu kontrol eder. Zero flagını kontrol eder yani (zero flagı bir önceki karşılaştırmadan karşılaştırılan şeylerin eşit olduğu bilgisini sağlar), flaglar cmp sonucuna göre belirlenir aynı registerlar gibi hafıza da sürekli olarak tutulur ve sürekli değişirler program çalıştığı sürece her cmp ve jump aşamasında flaglar kullanılır. jnz jump if not zero demektir yani sonuç sıfır değilse zıpla, öyleyse devam et anlamı taşır. Bu durumda eğer zero flag VARSA devam edicez YOKSA işimiz kötü çünkü doğrudan az önce geldiğimiz fonksiyona yönlendiriliyoruz orda hangi offsetlerin çağrıldığını hatırlatmama gerek yok sanırsam. İnvalid lenght, Invalid password...  
Peki zero flag için ne yapmamız lazım yani cmp opcode u na ne vermemiz lazım ki sonuç sıfır olsun, çıkardığı şeye bakıcak olursak (29h ->41) 41 karaktere ihtiyacımız var. Bu noktada bu karakter sayısının bizim için gereken şifre uzunluğu olabileceğinden şüphelendim ve gdb ile IDA daki bu yere breakpoint koyarak farklı girdilerime göre rax+28h ın nasıl değiştiğini gözlemledim. Şüphemde yanılmamışım bu bizim girdi uzunluğumuz. NOT: Elbette deneme yapmadan da assembly kodunu cemezüevveline kadar okuyup bunun argv[1] uzunluğu olduğunu anlayabilirdik ama ne gerek var merak edersen okuyabilirsin, bilgisayarlar bizi kandırmaz.  
Devam edelim, uzunluğumuzun 41 olması gerektiğini biliyoruz peki başka neler kontrol ediliyor?  
uzunluk doğru olunca bir kontrol daha yapılıyor burda girdimizin picoCTF{Success\n <password>\n} ile başlayıp daha bissürü anlamsız data ile devam eden bir veri ile karşılaştırıldığını gördüm ilk hetapta bayrağı bu sandım ama çok saçma olurdu zaten bu bayrağın uzunluğu 41 karakter bile değil yani 41 karakter uzunluğunda olması gereken girdimizin buna eşit olmasına imkan yok o yüzden jnz nun zıpladığı yere bakabiliriz.  
Evet burda daha mantıklı bir kontrol var rax register ımıza uzun bir hex sayısı atanıyor -> 7B4654436F636970h bunun ascii karşılığına baktığımızda "picoCTF{" olduğunu görüyoruz yani burda girdimizin başında "picoCTF{" yazıp yazmadığına bakıyor eğer aynısı değilse içinde invalid offsetlerinin bulunduğu bir fonksiyona yönlendiriliyoruz, nanay yani eğer aynı ise o zaman başka bir kontrol daha çıkıyor karşımıza burda iki kere son karakterimizin "}" olup olmadığı kontrol ediliyor. Bir kere kontrol ediliyor eğer değilse bir kere daha başka bir şekilde kontrol ediliyor bunun muhakkak bir nedeni vardır diye düşünüyorum ama anlamadım şuanlık ve eğer kontrolü geçtiysek yola devam ediyoruz geçemediysek girdimizin başında "picoCTF{" yoksa gidiceğimiz yere gidiyoruz.  
Bu noktada daha fazla ilerlemedim, bıraktım çünkü devamında bissürü kontrol daha vardı ve ben yorulmuştum sonuç olarak girdimizin bayrağın ta kendisi olduğunu anlamıştım.  
Şimdi izninizle bir test daha yapmak istiyorum şöyle 41 karakter uzunluğunda bir girdi oluşturup programın çıktısını inceliyelim:  
./checkpass picoCTF{91234567891234567891234567891234}  
Invalid password  
Evvet, işte tam olarak bunu bekliyordum.  
Artık uzunluğumuzun doğru olduğuna eminiz şimdi bruteforce yaparak 32 karakter uzunluğunda olabilecek bütün stringleri teker teker deniyelim, elbet biri doğru olacaktır.  
Şaka tabi, evimde bir kuantum bilgisayarı bulunmuyor böyle bir deneme 5.765,240,701,412,356 üzeri 48 yıl sürerdiki bizim bu kadar vaktimiz yok, öyleyse bize daha kısa bir çözüm gerek peki ne yapıcaz.  
  
An itibariyle merak ettiğim şey şu oldu, hangi noktada program benim şifremin yanlış olduğuna karar veriyor yani ilk hatayı nerde fırlatıyor bnu anlamak için breakpointleri olası programın devam ediş güzergahlarına yerleştirdim ve tam olarak nerde programın artık benim şifremin yanlış olduğunu anlamaya başladığını çözmeye çalıştım. NOT: sonradan yaptığım salaklığı şu şekilde fark ettim eğer kodu decompile etseydim direk ilk kontrol noktasının kolayca nerde olduğunu anlayabilecek mişim işte resmi:  
![ku582j7.jpg](/pictures/tht/ku582j7.jpg)  
burda sağ tık yapıp senkronize ederseniz assembly koduna geçtiğinizde tam olarak ilk kontrolün nerde yapıldığını görebilirsiniz.  
![q5p6kzv.jpg](/pictures/tht/q5p6kzv.jpg)   
bl,  ebx register ının ilk 8 bitidir bunun, gene IDA tarafından byte_39D95 olarak isimlendirilirmiş girince tek bytelık hexlerden lardan oluştuğunu gördüğümüz bir arrayın belirli indexindeki hex sayılarıyla  karşılaştırıldığını görüyoruz. Karşılaştırma başarılıysa bizi aynı şekilde başka bir byte karşılaştırmasına götürdüğünü görüyoruz eğerki karşılaştırma başarısızsa buda bizi IDA tarafından en altta yerleştirilen şu bloğa götürüyor:  
![jue3v13.jpg](/pictures/tht/jue3v13.jpg)  
Bu fonkisyon size çok tanıdık gelicek, evet ünlü, invalidler fonksiyonu...  
Amma çok şey buraya varıyormuş değil mi, eğer birkaç tane kontrol noktasını daha kontrol ederseniz hepsinin yukarda anlattığım gibi bir byte ı kontrol ettiğini ve değilse invalidler fonksiyonuna yönlendirdiğini görebilirsiniz peki bundan ne anlamamız lazım?  
  
Girdimiz şifrelendikten sonra teker teker programın istediği byte lar kontrol ediliyor biri bile yanlışsa doğruca aşağı, invalid fonkisyonuna yuvarlanıyoruz.  
İşte bu bize programda bruteforce yapmak için bir kapı aralıyor çünkü bütün şifrelenmiş string tek bir seferde kontrol edilmiyor sırayla teker teker... Bir saniye ben az önce sırayla mı dedim? Bunu nerden çıkardım ki, önce bu dediğimi kesinleştirelim:  
Yukardaki resimde bl kontrolünün olduğu yere gdb mizi açıp bir breakpoint yerleştirelim.  
ve girdimizi şöyle ayarlıyalım "picoCTF{kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk}"  
bu sayede şifremizin ne şekilde değiştiğini anlıyabileceğiz  
bu işlemleri gdb üzerinden yaptığımı hatırlatmak isterim nasıl yaptığımı bilmiyorsanız sormanız yeterli  
breakpointe vurduk, bl değerimizi kontrol edelim 0x2d çıktı yani k -> 0x2d ye dönüşmüş, bütün şifrelenmiş verimizi görmek için bl nin nerden bu değeri aldığını araştıralım, biraz yukarı bakınca bl nin bunu rsp register ı üzerinden aldığını görüyoruz bazı offsetler ekleniyor rsp ye sonra bl ye atılıyor değer ama bu offsetleri disassembler üzerinden şahsen ben kolaylıkla hesaplıyamıyorum bu yüzden kodun decompile halinden bakıcam:  
![nuv3mie.jpg](/pictures/tht/nuv3mie.jpg) ilk kontrol noktası,  
![c0304ex.jpg](/pictures/tht/c0304ex.jpg) işte değişkeni takip edip en yukarda onun aslında rsp register ının kaçıncı offseti olucağını görebiliriz -> rsp+0x48 şimdi buna gdb den devam edelim.  
En son kontrol noktamızda durmuştuk şimdi gdb üzerinden bu noktada rsp+0x38 register ında  hangi değerler olduğuna bakalım:  
(gdb) x/32x $rsp+0x38  
0x7fffffffdd08: 0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d  
0x7fffffffdd10: 0x2d    0x2d    0x2d    0xae    0x2d    0x2d    0x2d    0x2d  
0x7fffffffdd18: 0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d  
0x7fffffffdd20: 0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d  
  
çıktımıza gördüğümüz gibi bütün k ler aynı şekilde şifrelenmiş bu işimizi kolaylaştırıcak, şimdi sırayla olup olmadığına bakalım bunun için girdimi "picoCTF{skkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk}" şeklinde tekrardan oluşturuyorum ve gene breakpointe vurduk bakalım rsp üzerinde şimdi ne bulucaz:  
(gdb) x/32x $rsp+0x38  
0x7fffffffdd08: 0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d  
0x7fffffffdd10: 0x2d    0x2d    0x2d    0xdb    0x2d    0x2d    0x2d    0x2d  
0x7fffffffdd18: 0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d    0x2d  
0x7fffffffdd20: 0x2d    0x2d    0x2d    0x2d    0x2d    0xdb    0x2d    0x2d  
  
İlginç, sıra üzerinden değişmedi, ilk karakterimizi değiştirmemize rağmen şifrelenmiş halinde ilk karakter değil 30. karakterin değiştiğini görüyoruz. Yani biraz kafamızı kullanmamız gerektiği anlamına geliyor bu, peki ne yapmalıyız.  
İşin bu kısmında yukarda alıntıladığım kanaldan öğrendiğim bir toolu sizinle paylaşmak istiyorum ismi "valgrind" bu tool bir çok işe yarıyor öğrendiğim kadarıyla ama şuan sadece bir tanesiyle ilgileniyorum oda talimat sayıcı!  
kendim bu ismi verdim. Şu şekilde oluyor, toolumuzu şöyle açıyoruz:  
"valgrind --tool=cachegrind ./checkpass picoCTF{skkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk}" ve bize birçok bilgi veriyor:  
  
==314088== Cachegrind, a cache and branch-prediction profiler  
==314088== Copyright (C) 2002-2017, and GNU GPL'd, by Nicholas Nethercote et al.  
==314088== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info  
==314088== Command: ./checkpass picoCTF{skkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk}  
==314088==  
--314088-- warning: L3 cache found, using its data for the LL simulation.  
Invalid password  
==314088==  
==314088== I   refs:      468,685  
==314088== I1  misses:      1,803  
==314088== LLi misses:      1,738  
==314088== I1  miss rate:    0.38%  
==314088== LLi miss rate:    0.37%  
==314088==  
==314088== D   refs:      164,983  (114,715 rd   + 50,268 wr)  
==314088== D1  misses:      3,945  (  2,868 rd   +  1,077 wr)  
==314088== LLd misses:      3,245  (  2,237 rd   +  1,008 wr)  
==314088== D1  miss rate:     2.4% (    2.5%     +    2.1%  )  
==314088== LLd miss rate:     2.0% (    2.0%     +    2.0%  )  
==314088==  
==314088== LL refs:         5,748  (  4,671 rd   +  1,077 wr)  
==314088== LL misses:       4,983  (  3,975 rd   +  1,008 wr)  
==314088== LL miss rate:      0.8% (    0.7%     +    2.0%  )  
  
Benim şuanlık içlerinden tek anladığım şey şu ilk başta "==314088== I   refs:      468,685" yazan yer varya işte orası, bu refs sayısı artık neyse, benim anladığım programın çalışmasından itibaren çalıştırılan toplam talimat (instruction) sayısı ama başka bir şey de olabilir emin değilim. Programın ne kadar çalıştığı ile alakalı bir bilgi diyelim.  
Şimd bu ne işimize yarıcak diye soranlarınız olabilir yada benim bu cümlem bitmeden bir hışımla klavyeye çöküp aklına gelen parlak fikri hayata geçirmeye çalışanlar olabilir her türlü ben burdayım ve size anlatmak için varım.  
Planımız şu; bu tool sayesinde programın ne kadar çalıştığını anlıyabilme imkanımız var ve programın genel yapısı ile ilgili bir düşünücek olursak program verdiğimiz bayrağın önce 41 karakter uzunluğunda olup olmadığına sonra solunda "picoCTF{", sağında ise "}" olduğuna bakıyor, ardından bayrağın içindeki stringi cidden hardcore bir şifreleme sekansı var, işin sonunda şifrelenen bayrak iç verisini bazı byte offsetleri ile karşılaştırıp doğru olup olamdığına bakıyor doğru ise bir sonraki byte ı kontrol ediyor ki bunun sırasını biz bilmiyoruz (istersek güç uğraş öğreniriz tabiki ama buna gerek kalmayacak emin olun) en küçük bir hatada program invalid fonksiyonunu çağırıyor onunda içindeki işlemler bi hayli garip o yüzden çok yüzeysel geçtim bilerek. Yani harf harf kontrol yapılıyor. Hala anlamadıysanız şöyle açıklayayım. Bir saat tutun ve programın içine atılan girdilerin ne kadar sürede sonuç vericeğini ölçün, süre ne kadar uzun sürerse o kadar doğru gidiyoruz demektir. Ve evet buna  

### Timing Attack​

deniyor.  
valgrind tam olarak zamanı ölçmüyor ama daha iyisini yapıyor. Talimatları sayıyor, yani şu assembly kodunda satır satır çalıştırılan görevlerden bahsediyorum. Şimdi kafanızda bir şeyler oturduysa bayrağımızı bulmak için kullanıcağımız python scriptini sizlere takdim etmek isterim:  
  

```python
from pwn import *

flag_try_char = string.digits+string.ascii_letters+"_"

context.log_level = "error"
def count_instrucations(flag):
    valgrind_stderr = process([    "valgrind", "--tool=cachegrind", "./checkpass", "picoCTF{"+flag+"}"])
    valgrind_stderr.recvuntil("I   refs:")
    answer = int(valgrind_stderr.recvline().strip().decode().replace(",", ""))
    valgrind_stderr.close()
    return answer

def find_pass_index(base_chr):
    global best_count;
    search_indexs = [i for i in range(32) if collect_pass[i] == "*"]
    for i in search_indexs:
        try_pass = collect_pass[:i] + base_chr + collect_pass[i + 1:]
        print(try_pass)
        count = count_instrucations(try_pass)
        if count > best_count:
            best_count = count
            print("bir index buldum: "+str(i))
            return try_pass

collect_pass = "********************************"
best_count = count_instrucations(collect_pass)
print("kontrol için gerekli karakterler aranıyor...")
while any(c == "*" for c in collect_pass):
    for c in flag_try_char:
        count = count_instrucations(collect_pass.replace("*", c))
        if count > best_count:
            print(c+" sıradaki kontrol için gerekli, index aranıyor...")
            collect_pass = find_pass_index(c)
            print("yaklaşık şifre: " + collect_pass + ", aramaya devam ediyorum...")
            break
   
 
print("bitti.")
```

  
Gördüğünüz kod ne yapar kısaca açıklayayım:  
öncelikle şifrelenince bir kontrol noktasını bile geçemiyecek bir başlangıç şifresi belirler bu iş için "*" karakterini kullanmaya karar verdim. Sonra bu karakterle ilk girdimizi oluşturup komudumuzu çalıştırıyoruz pwn kütüphanesinden bu noktada bolca yararlandım. Bu şifreyi pico kalıbına sarıp girdi olarak kullandıktan sonra refs kısmından (yukarda bahsettim) talimat sayısını alıyoruz. Bu sayı bizim hiç bir kontrol noktasından geçemediğinde girdimizin elde ettiği sayı olucak. Sonra While döngümüzün şifremizde tek bir "*" kalmayıncaya dek çalışmasını sağlıyoruz. Ardından bir karakter seçiyoruz bu karakteri bütün yıldızların yerine koyuyoruz ve girdi olarak kullanıyoruz. Girdimizin kaçıncı indexinin kontrol ediliceğini bilmediğimiz için bütün yıldızları rastgele bir karakterle değiştirdik ve talimat sayısını hesaplıyoruz eğer sayı fazla ise bu şu anlama gelir: Bu karakter gerçek şifrenin bir parçası, ikinci aşama onun tam olarak şifremizin hangi indexinde olduduğunu bulmak bunun için teker teker yıldızları kaldırıp bu karakterimizi o yıldızlarla tek tek değiştiriyoruz taki talimat sayısının gene istediğimiz gibi uzadığını görünceye dek. Burda kodu iki aşamalı yapmamızın sebebi bütün karakterleri şifremizin her yerinde denemenin sadece kontrol noktasını geçtiğini bildiğimiz karakterleri şifrenin her yerinde demekten çok daha uzun sürücek olması.  
  
Bir süre kodun gerçek şifreyi bulmasını bekledikten sonra şifre karşımıza çıkıyor onu bu sefer elle pico kalıbına sokup bayrağımızı siteye teslim edebiliriz, bitti.  
  
KAPANIŞ:  
Çözüm bu kadardı, kafanızı kurcalayan veya neden yaptığımı anlamadığınız bir şey varsa sormaktan çekinmeyin. Gökkuşağı sevdalıları ve Kolaygelsingiller dışında, Hepinizin her türden yorumuna açığım. Bir sonraki CTF e kadar, Selametle kalın.
