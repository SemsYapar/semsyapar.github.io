---
layout: post
title: "secr3tfl4g - Crackme - basit düzey"
date: 2022-08-15
source: "https://www.turkhackteam.org/konular/secr3tfl4g-crackme-basit-duzey.2021931/"
---

PicoCTF teki crackme lerden sonra rotamızı bu sefer farklı kaynaklara çevirelim. Çok resmi olmasa ve denetlemesi iyi olmadığı için hatalarla sıkça karşılaşılabiliyor olsakta arada [crackmes.one](http://crackmes.one) dan da crackme çözerim. Farklı farklı insanların kendi crackmelerini yapıp paylaşabildiği ve çözebildiği bir platform burası.  
  
crackme linki: [Crackmes](https://crackmes.one/crackme/629d1dfe33c5d45b75903cd5)  
**AÇIKLAMA: **An easy to medium level crackme. Your objective is to find the hidden flag.  
                   Bizden programa gizlediği bayrağı bulmamızı istiyor haydi programa daha yakından göz atalım  
  
**Ön BAKIŞ: **programı açtığımız zaman, açılıp kapanıyor demekki kodda enter ı görene kadar cmd açık kalsın tarzı bir ibare yok direk açılır açılmaz ne yazdığını göremeden kapanıyor program, çözüm olarak exe nin olduğu dizinde bir cmd açın ve exe nin ismini ordan yazarak çalıştırın artık cmd yi ayrı bir uygulama olarak açtığınız için program çıkış yapsa dahi çıktısını görebileceksiniz.  
Gördüğümüz çıktı ise şu -> Hey who are you?! Get outta here! (bizden pek hoşnut olmadı galiba)  
  
Sitede zaten dosya türü belirtilmiş, ama emin olmak için genede DIE a dosyayı atıp bakabiliriz. (Siteden indirdiğiniz dosyalar zip şeklinde iniyor ve hepsinin şifresi de sitenin domain ismi ile aynı (crackmes.one)) zipten 2 adet çalıştırılabilir dosya çıkıyor biri linux diğeri de windows üzerinde çalıştırmak için ayrı ayrı derlenmiş dosyalar, ben kendi sanal makinemden kaynaklı bir sorun yüzünden linux dosyasını çalıştıramadım o yüzden çözümü windows üzerinden yapacağım.  
  
**ÇÖZÜM:**  
  
exe dosyamızı IDA ya atıyoruz ve main kısmını buluyoruz, start diyede geçebilir. Main kısmında bana anlanmlı gelen bir şeyle karşılaşmadım böyle durumlarda programın içindeki stringlere bakarım. Bunun için IDA da View->Open Subviews altında strings kısmına basabiliriz IDA bize bulabildiği bütün stringleri vericektir. İstediğiniz şekilde programı analiz edebilirsiniz, her yiğidin ayrı bir yoğurt yiyiş şekli vardır bunu öğreniyorsunuz zamanla ctf çözdüğünüz ve çözümlerini izlediğiniz zaman...  
Ben burda az önce karşıltığımız çıktıyı arattım ve buldum onun nerde çağrıldığına baktım ve analiz etmeye ordan başladım.  
  

![kmogzwh.png](/pictures/tht/kmogzwh.png)

  
if a1 <= 1 kontrolü argc sayısını kontrol ediyor. İsterseniz geriye dönerek kaynağını detaylıca kontrol edebilirsiniz hızlıca geçicem ben, ve evet 1 veya 1 den küçükse program çıkış yapıyor yani hiç argüman eklemediysek e tekabül ediyor bu çünkü programımızın ismi de bir argüman olarak sayılıyor, 1 o ediyor anlayacağınız. Biz ilk başt dümdüz çağırdığımız için programı direk bu hata mesajıyla karşılaştık ve ardından program çıkış yaptı.  
Bunu önlemek için argüman sayımızı arttırıp tekrar deneyelim mesela "secr3tfl4g.exe benim_argumanim" bu şekilde programı çağırdığımızda gene aynı çıktıyı alıyoruz peki bu ne demek, neden aynı sonuçla karşılaştık.  
  

![it3anla.png](/pictures/tht/it3anla.png)

  
Bu az önceki programın decompile edilmiş halinin devamı, gördüğüz üzere en altta bir kere daha yukardakinin aynısı bir hata mesajı daha fırlatıyor program. Bu demektir ki sadece argüman niceliği değil aynı zamanda niteliği de kontrol ediliyor ve muhtemelen beğenmediği için verdiğimiz argümanı, son noktada bu hata mesajını fırlatıyor program.  
Bu şekilde kodun bir aşağısına bir yukarısına bakıp, bakan kör gibi -help argümanını görmemeye çalışmam umarım sizi fazla delirtmemiştir Evet bende gördüm ortada program iki tane argümanın kontrolünü yapıyor birincisi -help ikincisi -h ve ikisinden birisinin olup olmadığına bakıyor. Bide altta bir argüman daha kontrol ediliyor -e diye, eğer programı çalıştırırken  yanına--help veya -h yazarsak argüman olarak. Şöyle bir çıktı veriyor bize:  
```
"secr3tfl4g.exe -h"  
  
Find the secret flag!  
  
Usage: secr3tfl4g.exe [--help|-h]  
  
Arguments:  
  --help, -h    Print this help message and exit.  
```
görünürde help dışında bir argümanı yok gibi gözüküyor ama IDA dan gördüğümüz kadarıyla -e diye bir argümanı daha var, eğer koda daha yakından bakarsanız bir çeşit enryption (şifreleme) işlemi gerçekleştiren bir argüman olduğunu görebilirsiniz. IDA daki strings kısmında buna dair ipuçları vardı:  
Unable to acquire crypto context.  
Unable to import key: 0x%08x  
Unable to encrypt: 0x%08x  
Unable to decrypt: 0x%08x  
  
Çıktı ise şu şekilde oluyor:  
"secr3tfl4g.exe -e banazorlactfcozduruyolaryardimedin"  
038f7ac35291c383ec799f805d3df1c9d54945a1eb5297563556c10b07c98dfb30b2441771af0dc9380a0d2ab5e3ff93  
  
Bir keyimizin olduğunu biliyoruz, yani şifreleme sistemi key kullanıyor ve girdimizi şifreliyor, linkte crackme nin çözümü de var orda adam şifreleme yönteminin adını elf dosyasını arayarak buluyor ama ben exe dosyasında bulamadım çokta umrumda değil açıkçası, bir anahtar olduğunu bilmek yeterli.  
  
Peki şu gizli bayrağımız nerde? Gizli şifreleme argümanımızı bulduk peki neyi kaçırdık, biraz daha aşağı kısma bakarsanız, şifreleme argümanımız tetiklendikten sonra hemen aşağısında bir işlemimiz daha var.  

![4irkxrs.png](/pictures/tht/4irkxrs.png)

  
Son hata mesajından hemen önce kontrol edilip çalıştırılan şu if bloğuna da bir bakın, gizli anahtarımızın üretildiği yer tam olarak burası işte, bunu şöyle anladım, ilk başta v13 değişkenine bir fonkisyonun geri dönüş değerinin verildiğini görüyoruz burdaki fonksiyon un içine atılan değere baktığımızda anlamsız bir veri ile karşılaşıyoruz, fonksiyona baktığımızda ise içinde windows crpyto kütüphanesinin decrpyt fonksiyonun bulunduğunu görüceksiniz. Az önce kurcaladığımız -e parametresi de tam tersi encrpyt fonkisyonunu çağırıyordu, bakarsanız görürsünüz.  
  
v13 e decrpyt edilmiş değer atanıyor ve bunun bizim argümanımızla aynı olup olmadığı kontrol ediliyor, yani gizli argümanımız tam olarak bu, ardından gene aynı decrpyt fonksiyonuna bu sefer farklı bir veri sokuluyor ve ekrana bastırılıyor. Decrpyt edilip ekrana bastırılan bu veri ise büyük ihtimal bizim bayrağımız. Bu noktada izlenicek şuan benim aklıma gelen yollar şu şekilde:  
  
1-) decpryt ve encrpyt fonksiyonlarında kullanılan anahtar statik veya dinamik analiz yapılarak bulunabilir ve gizli argümanı bilmeye hiç gerek kalmadan şifrelenmiş data decrpyt algoritması taklit edilerek çözülebilir.  
2-) dinamik analiz ile ne olduğunu bilmediğimiz argümanın bizim argümanımızla kontrol edildiği yere gidip önce decrpyt edilmiş argümanın ne olduğu öğrenilir ardından bu argüman kullanılarak program çalıştırılır ve programın şifrelenmiş bayrağımızı çözmesini ve ekrana basmasını seyrederiz.  
3-) dinamik analiz ile ne olduğunu bilmediğimiz argümanın bizim argümanımızla kontrol edildiği yere gidip jump condition tersine çevrilir bu sayede şifreli bayrağımızı çözücek fonksiyonu çalıştırmak için gereken gizli argümanı bilmeden bayrağı öğreniriz.  
4-) programdan bize bayrağı vermesi için rica edebiliriz.  
  
Ben ikinci yoldan gidicem çünkü gizli argümanın ne olduğunu da bilmek istiyorum ve daha çok zevk alıyorum.  
windows üzerinden debug işlem yapıcağım için x69dbg yi tercih ediyorum. Programı içine atarak çalıştırıyorum, argümansız çalıştırırsam hata mesajı alıcağımı bildiğim için rastgele bir argüman girmem iyi olur. Bunun için Dosya->komut satırını değiştir diyip kesme işaretleri arasında alınmış pogramın dosya yoluna hiç dokunmadan, kesme işaretlerinin dışına bir virgül atıp rastgele bir şey yazıyorum.  
  
daha önce debug kullanmadıysanız veya debug kullanmaya hakim değilseniz kodda bizim gitmek istediğimiz yere gitmek için şu adımları takip edebilirsiniz.  
sağ tık -> Ara -> Tüm Modüller -> String referansları, bunu yaptığınızda sizi Referanslar kısmına götürücek x69dbg ve programdaki bir dğeişken veya pointer a atanan bütün stringleri size göstermek için arama yapmaya başlayacak. Arama bittikten sonra alttaki filtreleme kısmına IDA da yaptığımız gibi hata mesajını yazarak onun hangi adreste kullanıldığını görebilirsiniz.  

![8731fi9.png](/pictures/tht/8731fi9.png)

Hatırlarsanız iki tane kullanıldığı yer vardı, birincisi programın başında argüman sayımızı kontrol ettiği sırada, ikincisi ise doğru bir argüman kullanmadığımız zamanda fırlatılıyordu.  
ikisinede breakpoint koymak için ayrı ayrı kullanıldıkları yere gidip üzerlerine de basabilirsiniz. Bu kısımda sağ tık yapıp tüm komutlara kesme noktası ayarla diyerekte bu işlemi yapabilirsiniz.  
Programımızı debugger üzerinden baştan başlatalım ve sağ ok tuşuna basarak ilerletelim bir süre sonra ikinci hata mesajımızın olduğu breakpointe çarptık eğer hiç argüman girmeden debugger ı başlatsaydık o zamanda ilk hata mesajına çarpardık. Burayı biraz inceleyelim ve IDA ile karşılaştırarak nerde olduğumuzu anlamaya çalışalım. Gitmek istediğimiz yer gizli argümanın decrpyt edildiği nokta, şuana kadar IDA da hep programın decompile edilmiş halini inceledik ama x69dbg de böyle bir özellik yok kodu sadece disassembly edebiliyor. Aradığımız yeri bulmak için IDA da v13 değişkeninin atandığı yerin üzerine gelip sağ tık senkronize et diyoruz. Ve dissassembly kısmına baktığımızda c kodunun assembly de tekabül ettiği yerin yeşil banda alındığı görebiliriz. O kısmı debugger üzerinde arıyoruz, hata mesajından çok uzak olmasa gerek, şöyle biraz yukarı bakarsak -e parametresini görebiliriz x69dbg bizim için hafızada okunabilir bir şey görünce o satırın yanında yorum olarak değeri yazıyor "-e" yazan yerde js koşullu zıplaması var, js tam olarak neye göre zıplıyor bilmiyorum ama IDA dan baktığımda zıplamazsa şifreleme işlemine başladığını zıplarsa ise gizli argümanımızın kontrol edildiği yere geldiğini görüyoruz. Argümanımız "-e" ise üçüncü argüman anahtar kullanılarak şifreleniyor değilse gizli argümanın kontrol edildiği yere zıplıyoruz. js den sonra zıplayacaksak yani argümanımız "-e" değilse çalıştırılıcak olan ilk talimat "lea rcx, ds:[0x00007FF70136A050]" işte bu talimat üzerine breakpoint koyalım ve programı tekrar başlatalım.  
  
Talimat üzerinde program durduğu zaman adım adım ilerlemek istediğimiz için ok tuşuna basarak değilde onun yanında açıklaması türkçe prosedürün içine girmeden devam et olan yamuk ok a basarak adım adım ilerliyoruz. Ve gizli argüman önce decrpyt edilmek üzere bir fonksiyonun üzerine sokuluyor -> call 0x00007FF701361C50, ardından bizim argümanımızla karşılaştırılıyor:  
mov rcx, qword ptr ss:[rsp+0x28]  
mov rdx, rax  
call 0x00007FF701361900  
test al, al  
je 0x00007FF701369811  
  
je den sonra eğer girdiğimiz argüman gizli argüman ile aynı ise bize bayrağı çözücek değilse ikinci hata mesajına zıplayacağız eğer 3. yolu seçseydik yapıcağımız tek şey burdaki je yi tam tersine çevirmek mesela jne yapmak olurdu yada zero flagı tersine çevirirdik ve flagı bulurduk ama 2. yolu izlediğimiz için şuan amacımız doğru argümanı bulmak. Adım adım ilerlerken gizli argümanın decrpyt edildiği fonksiyon bittikten sonra dönen değeri rax register ı üzerinden görebilirsiniz:  

![dd7fbgj.png](/pictures/tht/dd7fbgj.png)

  
Artık debugger ımızı kapatabilir ve büyük bir keyifle doğru argümanı girebiliriz:  
  
"secr3tfl4g.exe --d0n7l00k@m3"  
flag{w3ll_d0ne_y0ung_pad4wan}  
  
**KAPANIŞ:**  
Takıldığınız veya anlamadığınız bir nokta olursa yahut eleştirmek istediğiniz bir yer varsa uzattığım vesaire yazın nütfen. Beni ayrıeyeten keyiflendirmiş olursunuz. Selametle kalın.
