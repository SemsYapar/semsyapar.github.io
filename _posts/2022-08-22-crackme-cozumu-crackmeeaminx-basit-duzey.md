---
layout: post
title: "Crackme çözümü - CrackMe_EaminX - basit düzey"
date: 2022-08-22
source: "https://www.turkhackteam.org/konular/crackme-cozumu-crackme_eaminx-basit-duzey.2022429/"
---

Merhaba, güzelcik konuma hoşgeldiniz. Crackme çözerek tersine mühendislik skillerimizi geliştirebilir ve dışardaki haşin ve sert dünyaya karşı kendimizi hazırlayabiliriz Şuana kadar C# ile yapılmış bir crackme yi hiç paylaşmamıştım. Bu zinciri kırmaya karar verdim. Kolay anlaşılır - hem benim hemde sizin için - bir crackme buldum. Haydi çözüme geçelim. Zevkli dakikalar yaşamaya hazır olun.  
  
**GİRİŞ:**  
crackme nin linki -> [crackmes.one](https://crackmes.one/crackme/62b9678433c5d4251e723a0d)  
programı dümdüz açıyoruz, çok gaddarca geliyor ama ben çoğunlukla öyle yapıyorum. malwarebytes ın sildikleri hariç, siz önce virüstotal ile taratabilirsiniz.  
programı açtığımızda gördüğümüz manzara şu şekilde  

![pdyf2sk.png](/pictures/tht/pdyf2sk.png)

  
Alltaki buton tam çıkmamış "login" yazıyor.  
Görüldüğü üzere gayet basit bir isteği var, bir vaadide var, 50 dolar nerden baksan çok para demek...  
  
**ÇÖZÜM:**  
Önelikle dostum DIE ya programı atarak, çalıştırılabilir dosya hakkında ön bilgileri toplayalım.  

![7mdk3be.png](/pictures/tht/7mdk3be.png)

  
  
.net kullanılmış, vb.net ile de derlenmiş. Linkteki açıklamada belirtildiği gibi c# ile yazılmış olduğunu doğrulamış olduk böylece. Tabi .net demek sadece c# ile kodlandığı manası taşımaz, benim DIE de gördüğüm sonucu tam olarak neye yorucağım ile alakalı eksikliklerim var. Yani genel anlamda mimariyi anlıyorum ama DIE nın açıklamasındaki ayrıntıları anlayacak (mesela direk hangi dilin kullanıldığı) tecrübem ve bilgi birikimim yok. Bilgisi olanlar benide sizide aydınlatırlar bu konuda, belki  
  
Neyse söz konusu uygulama .net ailesinden çıkma olduğu ve gördüğümüz kadarıyla herhangi bir 3. part protector (DIE de öyle geçer, obfuscator asıl terimidir, amaç kodun insan tarafında okunmasını karmaşıklaştırmaktır) üzerinde kullanılmadığı için rahatlıkla dnspy üzerinden programımızı açabiliriz.   
  

![swqo0ky.png](/pictures/tht/swqo0ky.png)

  
  
  
Genel hatlarıyla programın bölümlerini görebilirsiniz aradığımız kısım, az önce programı çalıştırdığımızda gördüğümüz login kısmı, bunun bir buton olduğunu biliyoruz. 1 tane form var gözüken. Hadi orada olması gereken butonu arayalım.  
  

![owii6u5.png](/pictures/tht/owii6u5.png)

  
  
Zaten form1 i açar açmaz buton1 click event fonksiyonu karşımıza çıktı bu fonkisyon adından da anlaşılacağı üzere login butonuna bastığımız anda çalışan fonkisyonun ta kendisidir. Tabi isimlere aldanmamak lazım. Biraz aşağı inip form un oluşum kısmına bakarsanız buton a basıldığında ateşlenen fonksiyonun da bu olduğunu görüceksiniz. İçimiz rahatladığına göre devam edebiliriz.  
  
Garip yazılar görüyoruz string s ye Initialization diye bir fonkisyonun dönüş değeri veriliyor sonra bu base64 decode işlemine sokuluyor dönen byte değeride tekrardan stringe dönüştürüldükten sonra bu this.gu.text adı altında bizim girdimizle kıyaslanıyor (tekrar ediyorum eğer emin olmak istiyorsanız bunun bizim girdimiz olduğundan form un oluşturulma kısmına gidip kontrol edebilirsiniz) ve sonuç doğru ise çince bir sonuç yanlış ise de başka bir çince sonuç görüyoruz yada biz mi öyle sanıyoruz? İsterseniz programı dnspy dışında çalıştırıp bir deneme yaparak aldığımız sonucu burdaki karmaşık görüntü ile karşılaştıralım.  
  

![jd7gk6y.png](/pictures/tht/jd7gk6y.png)

  
  
Bu çince bir yazı değil, ingilizce bir hakaret. Peki neden böyle? Bu çince yazılar tam olarak ne ifade ediyor?  
  

![j0m35wa.png](/pictures/tht/j0m35wa.png)

  
  
Burasıda az çnce size ısrarla bazı şeylerden emin olmak için gidip bakmanızı söylediğim formun oluşturulma fonkisyonu form yaratıcı fonksiyon, formitator, formix, format, formyap, saçmalıyorum çünkü aslında ne olduğunu bende bilmiyorum. Daha önce hiç c# kodu yazmadım bu kısım nasıl oluşturuluyor veya gerçekte ne olarak adlandırılıyor, c# bilenler benle beraber diğer bilmeyenlere detaylı bilgi vericektir, belki  
  
Burayı şimdi size gösterme sebebim, bir çok yazının ve ismin de bu çince fonksiyondan etkilendiğini ve ondan dönen değerle belirlendiğini göstermekti. Yani programı çalıştırdığımız ilk andan itibaren bir çok şey bu fonksiyondan dönen değerlerle atanıyor. Programın geri kalan kısımlarına da bakarsanız bu fonksiyonun kullanıldığı daha çok yer bulucaksınız. Nasıl bir fonksiyon bu kadar çok işi yapabiliyor peki?  
  
Tabikide içine atanan değerlerle, fark ettiyseniz fonksiyonumuzun ilk argümanı olan çince yazılarımız hep farklı, 2. argüman olan fazla basamaklı sayılarda öyle, bu bir çeşit şifreleme olabilir mi dediğinizi duyar gibiyim. Kesinlike!  
  

![6iw05jq.png](/pictures/tht/6iw05jq.png)

  
  
Fonksiyonun içine baktığımızda aslında basit bir şifrelem fonksiyonu olduğu görüyoruz bir foreach döngüsünü içinde barındıran minik, cücücük bir fonkisyon bu.  
"^" <- bu işareti daha önce gördünüz mü veya kullandınız mı biliyorum ama ben gördüm ve kullandım, anladığım kadarıyla basit ctf soruları yapmak için geliştirilen bir sembol, başka bir amacı yok tabiki bundan fazlası o ama ben onu çoğu dilde tekabül ettiği XOR operatörüyle tanıdım. XOR bir mantık kapısıdır OR operatörünün başına X gelmesiyle oluşur X, exclusive anlamına gelir. Olayı ise şudur. Bildiğiniz gibi tüm karakterler aslında bilgisayar için byte larla ifade edilir. Bu sebepten bir string oluşturmak istediğimizde bu byteları yan yana koyarız ve cümleleri bu şekilde bilgisayarlarımız kaydeder, paylaşır, düzenler vs.   
  
Peki XOR operatörü napar, türkçeye "yada" olarak geçmiştir. Karşılaştırılan değerlerin ikisi birbirinden farklıysa doğru aynı ise yanlış, durumunu kontrol eder. bu bir stringde mesela "sems" kelimesini ele alalım. s harfi 8 bit ten oluşutur her bit 0 veya 1 dir. bunu "yapar" kelimesi ile XOR ladığımızda dizideki ilk harflerin ilk bitleri karşılaştırılır farklılar ise sonuç 1 değillerse 0 olur. Bu sayede ortaya çıkan string XOR işleminin sonucu olur.  
  
Gördüğünüz fonksiyon da aynen bunu yapıyor önce çince kelimeden bir harf alıyor sonra bu harfi 2. argüman olan sayı ile XOR luyor. Yani tabiricaizse sayı bizim key imiz, çince cümle ise bizim  şifreli metnimiz oluyor. Bunu anladığımıza göre formda butona basıldıktan sonra çalışan fonksiyonda bizim değerimiz ile karşılaştırılan [@String](https://www.turkhackteam.org/uye/530377/) değişkeninin oluşturulduğu bloğa bir breakpoint koyalım ve geri dönen değeri okuyarak doğru girdiyi bulalım ne dersiniz buna? Haydi yapalım.  
  

![se3iqb0.png](/pictures/tht/se3iqb0.png)

  
  
25 ıncı satırın solundaki gri bölgeye tıklayarak dnspy da breakpoint koyabilirsiniz. Ardından yukardaki Başlat butonuna basarak programımızı debug (hata ayıklama) etme işlemine başlayalım.  
Bu noktada eğer dnspy ın 32bit versiyonunu kullandıysanız hata vericektir, program 64 bit destekli çünkü, bu yüzden 32 bit yerine 64 bit dnspy versiyonu çalıştırarak debug işlemine ordan devam edebilirsiniz.  
Başlat butonuna bastıktan sonra form yüklenmiş bir şekilde karşımıza geliyor. breakpointi tetiklemek için login düğmesine basalaım. Bir şey yazmaya gerek yok, programda bu kontrol edilmemiş.  
Login butonuna bastıktan sonra program breakpointimize vurucaktır. Bu noktada şifre çözücü fonksiyonun çalışması için bir adım atmamız gerekli ki sonucu görelim bu yüzden yukarda türkçe "e/a git" yazan yamuk oka basarak bir adım atıyoruz. Şimdi aşağıda bir string gözüktü ama tahmin edersiniz ki bu bizim asıl doğru girdimiz değil çünkü birazdan base64 decode işlemine sokulacak bunu biliyoruz ve bir adım daha atıyoruz. Şimdi elimizde byte değerleri oluştu bir adım daha atarak bu byteların oluşturulan string karşılığını görebilirsiniz.  
  
Evet değerimiz gözüktü, belki anlatışım kafanızı karıştırmıştır diye debug işleminin son halinin fotorafını atayım.  

![cn4tlvl.png](/pictures/tht/cn4tlvl.png)

  
  
Dnspy ı kapatabiliriz, programı dümdüz açıyoruz ve doğru girdiyi yazıyoruz.  
  

![cm5g3gu.png](/pictures/tht/cm5g3gu.png)

  
  
**KAPANIŞ:**  
Diyor ama link bir yere varmıyor ne yazıkki, 50 dolar işi hayal oldu ama umarım crackme çözümünden keyif almışsınızdır. Herkese hayırlı günler, selametle kalın.
