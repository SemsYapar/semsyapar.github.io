---
layout: post
title: "gogo - Crackme - basit düzey"
date: 2022-08-01
source: "https://www.turkhackteam.org/konular/gogo-crackme-basit-duzey.2020945/"
---

Selam herkese, CTF çözümüme hoşgeldiniz bugün [https://play.picoctf.org/practice/challenge/171?category=3&page=2](https://play.picoctf.org/practice/challenge/171?category=3&page=2) linki üzerinden ulaşabileceğiniz bir crackme yi çözeceğiz dilerseniz başlayalım.  
  
**Öncelikle soruyu tanıyalım:**  
Hmmm this is a weird file... [enter_password](https://mercury.picoctf.net/static/19ee4f8771173cbddb36ca81481f862f/enter_password). There is a instance of the service running at mercury.picoctf.net:4052.  
  
enter_password isimli dosyayı linux sanal makineme atıyorum ve çalıştırıyorum şu şekilde bir girdi - çıktı görünümü var:  
./enter_password  
Enter Password: asdasdsa  
  
basit bir arayüz, istediği fazla bir şey yok. Şu şifrenin ne olduğunu bulalım ardından açıklamada belirtilen sunucuya yazarak bayrağımızı alalım.  
Dosyayı daha çok hoşuma gittiğinden IDA üzerinden inceliyeceğim siz isterseniz ghidra veya farklı bir disassembler da kulanabilirsiniz. Aynı zamanda IDA ve Ghidra nın c/c++ decompiler larıda var buda işimizi kolaylaştırıp kodu daha çabuk anlamamıza vesile oluyor.  
  
**ÇÖZÜM:**  
Dosyayı açtığınızda birsürü fonksiyonu olduğunu görüceksiniz kısmen büyük bir c/c++ crackme si diyebilirdik ama dosyanın main fonkisyonlarını inceleyince ve DIE üzerinden de bakınca go ile yazıldığını anlıyoruz.  

![ghmngti.png](/pictures/tht/ghmngti.png)

  
  
Eğer çalıştırılabilir bir dosyanın fonkisyonlar kısmında IDA da bu şekilde main_ diye giden bir ifade şekli görürseniz bunun go ile derlendiğini anlayabilirsiniz. Ben böyle anlıyorum belki daha açık bir yolu vardır. Biliyorsanız yorumlarda belirtin nütfen.  
  
main_main dosyamızın başlangıç kısmı:  

![840ildx.png](/pictures/tht/840ildx.png)

  
İlk blokta enter password metninin printf ile bastırıldığını sonrada scanf ile bizden girdi alındığını görüyoruz. Sonrada checkPassword fonksiyonu çağrılıyor, içine bakalım.  
  

![aftrbwg.png](/pictures/tht/aftrbwg.png)

  
cmp ecx, 20h ile girdimizin uzunluğunun 20h yani 32 karakter olup olmadığı kontrol ediliyor.  
  

![7ww2z1k.png](/pictures/tht/7ww2z1k.png)

  
esp register ının üzerinde belli bir ofset ekleniyor ve içi muhtemelen bir string ile dolduruluyor. IDA kodu analiz ettikten sonra bu offseti key olarak yazma  kararı almış demekki önemli bir sebebi var.  
  

![5p3kz0e.png](/pictures/tht/5p3kz0e.png)

  
Talimatların devamında bir döngünün içerisinde buluyoruz kendimizi burası çok kritik. Döngü demek kontrol demek. Bir stringi bir stringle adım adım karşılaştırmak demek. Tabi basit düzey crackme ler için konuşuyorum, hadi adım adım inceleyelim.  
  
gene uzunluk karşılaştırması ile başlıyor talimatlarımız ama bu sefer biraz farklı zaten 32 karakter olduğu için girdimiz buralara kadar geldik bu sefer amaç 32 karakterlik bir stringin tamamını dolaşmak aşağıda eax ın "inc eax" taliamtıyla her döngü bitişide bir arttırıldığını görebilirsiniz. bir önceki resime bakarsanız eax ın sıfırlandığını anlayacaksınız eax for döngüsünün i si bu durumda umarım anlatabilmişimdir.  
Ardından eax edx karşılaştırması yapılıyor önceki resime bakarsanız edx bizim girdimizin uzunluğu neden tekrar kontrol ediliyor anlamış değilim. Go işte...  
Sonra cmp eax 20h ile tekrar uzunluk kontrolü yapılıyor ne diyeceğimi bilemiyorum lakin burda atlanmaması gereken nokta var oda birazdan kullanacağımız ebp register ına ecx in eax eklenmiş halinin bir byte ı yani bir karakterinin atanmış olması bunu anlamak için önceki resimde ecx in neye tekabül ettiğine bakmanız lazım IDA nın burda işimizi bir hayli kolaylaştırdığı bir gerçek direk offseti input.str olarak tanımlamış ve bu adres ecx e verilmiş. Yani ecx bizim girdimizin adres değerini tutuyor ebp ye bu girdimizin bir harfini verdik ve döngü bitene kadar bütün harflerini teker teker vereceğiz.  
ve kontrolün yapıldığı asıl bloğa geçtik. Burayı adım adım okuyacak olursak; önce esi register ına yukarda biraz önce key offseti doldurduğumuz değerler atanıyor ama eax ı ekleyerek yapıyoruz bunu yani eax 0 dan başlamak üzere önce 1,2,3 diye giderken sırayla bu key değerlerini alıcak esi, sonra esi yi ebp ile xor luyoruz ebp, girdimizin eax indexindeki harfiydi unutmayın. xor lanan değer ilk argümana aktarılır bu durumda sonuç ebp de, bir aşağıda esi ye yeni bir değer verildiğini görüyoruz gene eax index olarak kullanılıyor ve esp nin daha önce görmediğimiz bir offsetini kullanıyoruz.  
xchg opcode u bir değeri diğeriyle değiştirmeye yarıyor en bast anlatımıyla internetten araştırınca öyle anladım ben yani; ebp eax ile değişiyor, esi ise ebx ile bu durumda eax ta girdimiz ve key ile xor lanan karakterimiz, ebx de ise ne olduğunu bilmediğimiz bir stringin eax ıncı elemanı var bu ikisi karşılaştırılıyor. Sonuç aynı ise yani ikisi birbirinden çıktığında 0 ediyor ise (cmp opcode u tam olarak bunu yapar) ebx değerimiz 1 arttırılıyor eğer aynı değil ise arttırılmıyor bu şekilde bütün girdimiz key ile teker teker xor lanıp şuanlık bilmediğimiz esp üzerindeki bir string ifadesi ile karşılaştırılıyor. döngü bitince ebx in 20h yani 32 olup olmadığı kontrol ediliyor yani bütün karakterlerin doğru olması gerekiyor, sonuç doğru ise fonksiyonumuz 1 değilse 0 dönüyor işte main_checkpassword fonksiyonu tam olarak bunu yapıyor.  
  
Yapıyı tamamıyla anladık, doğru girdiyi üretmemiz için artık kolları sıvamamız lazım key i biliyoruz oluşturulma aşamasını IDA üzerinden gördük önceki resimlerde, e girdimizi pek tabi biliyoruz çünkü biz giriyoruz.D bu ikisi xor lanıyor bunu da anladık. Peki ney ile karşılaştırılıyor bunu anlamak için IDA da yaptığımız statik analize elbette devam edebiliriz ama ben bu tür stack pointer üzerinden okunan - çekilen değerler ile uğraştığım zaman kolayıma geldiği için dinamik analize geçiyorum gdb üzerinden okumak istediğim yere breakpoint koyuyorum ve değerimi okuyorum. Gene böyle yapıcam amacımız gdb ile IDA da gördüğümüz esp+eax+44h+var_20 offsetindeki stringe ulaşmak ve xor lanan girdimizle karşılaştırılan o stringi bulmak. Hadi yapalım şu işi.  
  
gdb ile dosyamı açıyorum, assembly kodunu intel yansımasıyla okuyabilmek için "set disassembly-flavor intel" komutunu giriyorum.  
c/c++ dosyası olsaydi info files komutu ile section (bölüm) lara bakardık ve .text section una breakpoint koyardık çünkü orası programın başladığı kısımdır ama go ile derlenmiş bir kod var karşımızda go nun entry point ini nasıl bulacağımı bilmiyorum bu yüzden IDA nın hesapladığı offsetleri kullanıcam.  
IDA da "movzx   esi, [esp+eax+44h+var_20]" bu talimatın üzerine basıyorum aşağıda bunun programın kaçınca offseti olduğunu söylüyor bize neymiş, 80d4b28 buraya breakpoint koymak için gdb üzerinden şu komutu çalıştırıyorum "b *0x80d4b28" ve programı "r" komutu ile başlatıyorum. bizden şifre istiyor, planladığımız yere varmak için bu şifrenin 32 karakter uzunluğunda olması gerektiğini biliyoruz. 32 tane "s" yazıp enter lıyorum ve breakpointe vurduk  "x/10i $eip" komutu ile programın birazdan işleyeceği 10 instruction (talimat) ı instruction pointer üzerinden okuyabilirim çünkü instruction pointer her zaman işlenicek bir sonraki instruction ı gösterir programa bu işe yarar gdb de bir adresi bastırmak için x komutu kullanılır ordaki veriyi nasıl yansıtacağımızı da "/" koyduktan sonra belirtiriz "i" yazarak adresin işaret ettiği değerin bir instruction olarak bastırılması gerektiğini söylüyorum gdb ye ve i den önce "10" yazarak birazdan çalıştırılıcak instruction la beraber devamındaki 10 instruction u görebiliyorum.  
Tam olarak IDA da gördüğümüz yerdeyiz şimdi dilerseniz karşılaştırılan stringin ne olduğunu görelim. talimatımız gdb de "movzx  esi,BYTE PTR [esp+eax*1+0x24]" şeklinde gözüküyor okumak istediğim kısım "esp+eax*1+0x24" bu adresin gösterdiği ilk 32 karakteri görmek için şu komutu kullanıyoruz "x/32x $esp+$eax*1+0x24" 32x demek ilk 32 hexadecimal sayısını bastır bu adresin anlamına geliyor ve sonucu sayılardaki 0x lerden ve adres gösterimlerinden temizleyince şu hale getiriyoruz:  

![qrumxmp.png](/pictures/tht/qrumxmp.png)

  
"4a53475d414503545d025a0a5357450d05005d555410010e4155574b45504601" bu karşılaştırılan karakterlerimiz işte şimdi eldeleri toplama zamanı  
IDA üzerinden daha önce gördüğümüz keyi de gdb üzerinde görebiliriz onun nasıl gözüktüğünü bulmak için az önceki komutumu biraz değiştirerek şu hale getiriyorum "x/10i $eip-0x10" böylece eip register ından 0x10 hex çıkararak daha önceki instruction ları görebiliyorum işte key den bir byte okuduğumuz kısım orda bakın:  

![ht8qmi3.png](/pictures/tht/ht8qmi3.png)

  
Key in IDA da nerde tanımlandığını unutanlar için IDA da oluşturulduğu yeri de şöyle göstereyim:  

![2xh4ogl.png](/pictures/tht/2xh4ogl.png)

  
  
adresimizin işaret ettiği ilk 32 karakteri okumak için aynı şekilde gdb üzerinden "x/32x $esp+$eax*1+0x4" komutunu kullanabiliriz ama daha öncesinden soruyu çözdüğümden bu değerin full ascii karakterlerinden oluştuğunu biliyorum bu yüzden gdb nin bu hex sayılarının bizim için ascii karşılıklarını bastırmasını isteyebiliriz  bunun için komutu "x/s $esp+$eax*1+0x4" yaparak değiştiriyorum tahmin ediceğiniz gibi "s" stringi ifade ediyor ve aldığımız sonuç şu şekilde:  

![tmahx7n.png](/pictures/tht/tmahx7n.png)

  
ilk 32 karakterini kullansak yeter gdb büyük ihtimal null karakteri görene kadar okumaya devam etmiş stringi, null karakter c dilinde stringlerin hafızada nerde bittiğini belirtmek için stirngin sonuna koyulur debuggerlarda bir stringi okumak için null karakteri bitiş noktası olarak kabul ederler böylece bir şeyler bir şeylere karışmaz. Bütün stringler null karakter ile bitmez lakin bunun detayını pek bilmiyorum bilen varsa işin ayrıntısını konu altında bana da anlatsın nütfen. Şimdilik ilk 32 karakterimizi alalım:  
"861836f13e3d627dfa375bdb8389214e" bu bizim girdimizle xor lanan key işte. aslında devamındaki kısımda az önce hex sayılarını bastırdığımız karşılaştırma yapılan string ama o tamamen okunabilir karakterlerden oluşmadığı için sadece belli bir kısmı çıkmış.  
 Şimdi yapacağımız şey basit girdimiz key ile xor landıktan sonra bir string ile aynı olup olmadığı kontrol ediliyor. Şuan elimizde hem karşılaştırılan string hemde xor key var, doğru keyi bulmak için xor un geri dönüş özelliğini kullanabiliriz çünkü mesela a ile b xor landığında c olursa c a ile xorlandığında b yi b ile xor landığınd a yı verir. Daha fazlasını öğrenmek istersenix xor mantık kapısını internette araştırabilirsiniz bu sayede çok tatlı keyler ortaya çıkarılıyor. Bu işlemleri python da bir script yazarak da yapabiliriz ama bu sefer bunu [CyberChef](https://gchq.github.io/CyberChef/) sitesi üzerinden yapmak istiyorum. Burda bir sürü metot ile şifreler oluşturabilir ve onları çözebilirsiniz çok tatlı bir site.  
karşılaştırılan stringi anahtar ile xor layarak doğru girdimizin ne olması gerektiğini öğrenebiliriz işte böyle:  

![pjkb957.png](/pictures/tht/pjkb957.png)

  
 girdimizi bulduk şimdi bunu yazalım bakalım ne olacak.  
Enter Password: reverseengineericanbarelyforward  
=========================================  
This challenge is interrupted by psociety  
What is the unhashed key?  
  
bizden daha öncesinde hashlediği bir keyin ne olduğunu soruyor. Aranızda eminim istediği şeyin ne olduğunu şıp diye anlayanlar vardır. Acaba keyimizin 32 karakter olması bir tesadüf olabilir mi? Çokta hash e benziyor he...  

![ff6rtl9.png](/pictures/tht/ff6rtl9.png)

  
evet bir hash miş ve "goldfish" in hashlenmiş haliymiş.  

![5glhtc5.png](/pictures/tht/5glhtc5.png)

  
Doğal olarak bayrak bizde olmadığından böyle bir çıktı verdi program bu girdileri burda değil sorunun açıklama kısmında verilen sunucuda çalıştırmamız lazım bayrak orda:  

![i1dly5k.png](/pictures/tht/i1dly5k.png)

  
  
**KAPANIŞ:**  
İşte bu kadardı, sorularınız varsa yazmaktan çekinmeyin kafanızı kurcalayan her soruyu bana özelden yazabilir veya konu altında paylaşabilirsiniz. Saçma bir şey yaptıysam onuda yazın mantıksız bir yol izlediysem belirtin, yazım yanlışlarım olabilir kusura bakmayın. Selametle kalın.  
  
**EKSTRA:**  
Konuyu yazarken döngüde dinlediğim müzik ektedir: 

<iframe width="560" height="315" src="https://www.youtube.com/embed/4w3VqzwJ1j4" frameborder="0" allowfullscreen></iframe>
