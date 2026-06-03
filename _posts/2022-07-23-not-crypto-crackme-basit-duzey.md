---
layout: post
title: "not crypto - Crackme - basit düzey"
date: 2022-07-23
source: "https://www.turkhackteam.org/konular/not-crypto-crackme-basit-duzey.2020351/"
---

Selamlar herkese, bugün bir ctf çözümü yapmak için burdayız. Konu olan ctf sorusu PicoCTF sitesi üzerinde yayınlanıyor. linkini şöyle bırakayım benle beraber çözmek istersiniz diye, crackme yi yüklemeden öncesinde oturum açmanızı istiyecektir.  
[https://play.picoctf.org/practice/challenge/222?category=3&page=2](https://play.picoctf.org/practice/challenge/222?category=3&page=2)  
  
soru açıklamasında: "there's crypto in here but the challenge is not crypto... " , bir şifreleme var ama challenge(türkçesini unuttum) bir şifreleme olmaması demiş. Ne kast ettiğini şimdilik bilmiyoruz.  
  
Dosya elf executable, linux çalıştırılabilir dosyası yani. Önce sanal makinemize atalım ve nasıl bir girdi, çıktı sağladığına bir bakalım.  

![il3vzou.png](/pictures/tht/il3vzou.png)

  
  
Bizden aldığı girdiyi beğenmemiş olacak ki sonra tekrar gel diye bir mesaj attı sadece. Şimdi programımızı biraz karıştıralım. Programı IDA ya atıyorum ve main kısmına bakıyorum:  

![4r6m68z.png](/pictures/tht/4r6m68z.png)

  
Burda programı ilk çalıştırdığımızda bizden girdi almadan önce ne yaptığını görebiliyoruz. call puts yardımı ile bir kısmını görebileceğiniz başlangıçta kullandığı stringi bastırdığını görüyoruz. Şimdi biraz daha aşağılara, bizden girdi aldığı yerleri bulmaya çalışalım. Bunun için scanf veya türevi standart input alan fonksiyonları dikkatle taramamız gerekiyor. Ben çok aşağı inmeden bir tanesini buldum, işte:  

![84ctfio.png](/pictures/tht/84ctfio.png)

temel c fonksiyonlarından biri olan fread in çağrıldığını görüyoruz parametreler fonksiyonun biraz yukarısında register larımıza aktarılmış. 64bit mimaride çalıştığı için program. Pushlama şeklinde değilde registerlara değer atama şeklinde önceliklenir argümanalrın fonksiyonlara atılma sekansı.  
Şimdi argümanalra baktığımızda fread için gereken 4 argümanın da hazırlandığını görüyoruz, herzaman tam olarak bilmediğiniz bir fonksiyon gördüğünüzde önce onu internette aratın ve parametrelerini öğrenin böylece neyi aramanız gerektiğini anlıyabilirsiniz. Mesela fread için parametreleri şu şekilde öğrendim ben:  

![pp674jv.png](/pictures/tht/pp674jv.png)

  
Gördüğünüz gibi ilk parametre verinin aktarılıcağı pointer, ikincisi okunucak her elementin kaç byte olucağına karar veren bir değişken, üçüncüsü kaç tane elementin okunağına karar veren bir değişken ve dördüncüsü okuma işleminin nerden yapılacağını belirleyen bir pointer. Şimdi IDA ya daha yakından bakalım:  

![m3tecgj.png](/pictures/tht/m3tecgj.png)

  
Zaten IDA bu fonkisyonları babası kadar iyi tanıdığı için otomatik yorum satırı ekleyip bize kendi dili döndüğünce tarif etmeye çalışmış, gördüğünüz gibi son argüman olan en sonda rax register ına mov lanan stdin_ptr bize bu okuma işleminin terminalden yapılıcağına dair bir fikir veriyor ayrıca edx register ına aktarılan 40h ise decimal olarak 64 e tekabül ediyor yani bizden 64 karakter okuyacak terminal üzerinden...  
  

![il3a4r7.png](/pictures/tht/il3a4r7.png)

  
Programın devamında uzunca bir kısmında anlamsız gelen atamalar var, xor işlemleri, döngüler, eklemeler, çıkarmalar... bizden aldığı girdiyi şifrelediğini düşünebiliriz, hiç bir şey yapmamış da olabilir bunu bilemeyiz bütün talimatları tek tek okumak istemeyiz çünkü... Dimi istemeyiz!?  
Sol altta gördüğümüz resim bizim içinde bulunduğumuz talimatlar havuzunu gösteriyor, gördüğünüz gibi bir hayli aşağılara iniyor bakarsanız bunların hepsinin kullanılan şifreleme alogirtmasının bir parçası olduğunu görüceksiniz, şimdi en aşağıda asıl görmemiz gereken önemli kısmın olduğu yere gelelim, karşılaştırma anı.  

![a9jifp6.png](/pictures/tht/a9jifp6.png)

  
Ayrılık tam bu noktada oluyor memcmp fonkisyonumuz çağrılıyor bu fonksiyon 3 argüman alır ilk ikisi karşılaştırılıcak yerlerin pointer larıdır üçüncüsü ise karşılaştırılıcak byte uzunluğudur (internetten baktığımda argüman sıralaması öyleydi burda ise önce bizim string register e atanıyor sonra karşılaştırılıcak uzunluk sonra karşılaştırılıcak string, nedenini anlıyamadım, çok da problem değil) gördüğünüz üzere bu uzunluk 40h yani 64byte aynı girdimizin uzunluğu kadar demekki şifrelenen girdimizin boyutu değişmemiş yada zaten şifrelenmemiş sadece kafamızı karıştırmak için bir dizi yoğun işlemden geçirilmiş buda soruyu hazırlayanın ilk başta dediği şeye uyuyor.  
Karşılaştırmanın nerde yapıldığını IDA ile öğrendik, statik analizimizi tamamladık şimdi dinamik analiz zamanı yani programı çalışırken gözlemleyip tam belirlediğimiz noktada register lara yüklediği stringleri okumalıyız böylece doğru şifreye ulaşabiliriz. NOT: Bu soruda böyle ama şöyle bir senaryoda olabilirdi, bir bakardık ki girdimizle karşılaştırılan string anlamsız karakterler içeriyor yani bayrak değil. Ve onu girdi olarak verdiğimizde yanlış olduğunu söylüyor olabilirdi program bize bu bizi şuna iterdi. Demekki derdik girdimiz öyle alalade karşılaştırılmıyor önce şifreleniyor sonra şifrelenmiş hali karşılaştırılıyor ve o zaman az önce hıphızlı geçtiğimiz uzuuun ve şifreleme olabileceğinden şüphelendiğimiz algoritmanın başına oturur, kağıt kalem çıkarır ve bunu tersine çevirerek doğru şifrelenmiş girdiyi elde etmek için gereken doğru girdiyi oluşturmaya çalışırdık. Bu da başka bir videonun konusu olsun Bu iyi günlerimiz.  
  
Programımı gdb üzerinden açıyorum main fonksiyona ulaşmak için sembolü deniyorum (b *main) ama sembol yok bu yüzden info files diyerek programın section (bölüm) lerine bakıyorum .text section u talimatların başladığı ve entry point in (programın çalıştırılmaya başladığı nokta) bulunduğu kısımdır bu yüzden onun başlangıç adresine breakpoint koymak en iyisi ama programı birkere "r"komutu ile runlamadan bu adresler doğru adresler olmıyacak, gdb de aslr normal olarak kapalıdır siz açmadığınız sürece bu ne demek? Normalde programlar içerisinde ramde hangi bölümün hangi offset üzerinde barınıcağı bilgisini tutar modern işletim sistemleri bunu bir güvenlik zaafiyeti olarak görür ve programı ramde her yüklendiğinde rastgele bir bölgeye yerleştirir buna kısaca ASLR denir. gdb de adreslerle sürekli uğraşmamamız için aslr otomatik olarak kapatılır. Her defasında breakpointleri yenilemek gibi saçma şeylerle uğraşmamak için gibi düşünün. Ama genede kendisi sürekli olarak yerleştireceği adresleri siz programı bir kere çalıştırmadıkça info files üzerinde belirtmez. Belki adresleri yüklemek için bir yol vardır ama ben böyle biliyorum. Neyse çok uzatmıyalım bir kere runladık programı gdb üzerinden sonra info files dedik ve .text section un başlangıç adresini kopyaladık şimdi "b *<başlangıç_adresi>" komutu ile oraya bir breakpoint koyalım ve programı tekrar yeniden başlatalım.  Ardından "x/20i rip" komutunu kullanarak rip register ımızın tuttuğu adres değerindeki talimatları görelim (rip register ı assembly kodunda çalışıcak bir sonraki talimatın yerini gösterme amaçlı kullanılan çok önemli bir register dır). x istediğimiz register ın adresine ulaşmak için kullanılır yanına gelen şey ise adresten döndürmek istediğimiz tipi belirtir bizim durumumuzda bu "i" yani instruction (talimat) yani assembly talimatları, başına eklediğimiz 10 da başlangıç adresi ile beraber 10 satır talimat göster demek, işte bu kadar kolay. Görebileceğiniz üzere printf fonksiyonu hemen gözümüze çarptı bu demektir ki main fonksiyonun direk içine gelmişiz. Bu beni şaşırttı çünkü önce libc_start_main fonkisyonuna gideriz diye düşünmüştüm. main fonksiyon çağrılırken kullanılır pek bilmemekle ve anlık olarak sallamakla beraber direk main e düşmemizin sebebinin programın main fonksiyonu yazılırken argüman kısmının boş bırakılmış olmasından dolayı olduğunu düşünüyorum daha iyi bilenler beni yanlışsam düzelticeklerdir. Şimdi memcmp fonksiyonunu görene kadar talimatları istemeye devam etmeliyiz gdb den. Şöyle yapıcam "x/500i rip" böylece bayağı bir talimatı listelemiş oldum. En aşağılara kadar gittim ve işte tadaa, memcmp orda duruyor. Artık yanındaki adres değerini öğrendiğimize göre oraya bir breakpoint ayarlıyabiliriz. "b *0x5555555553b9" yazarak breakpointimi koyuyorum şimdi tekrar run lıycam programı, önce ilk bıraktığımız breakpointe vurduk hatırlarsak bu main fonksiyonun başlangıcıydı şimdi "c" yazıyoruz continue anlamında, program bizden girdi istiyor fread e ulaştık sanırım rastgele 64 karakter yazıyorum ve gönderiyorum ve asıl istediğimiz breakpointe vurduk, memcmp çağrılmadan hemen öncesindeyiz bir adım sonra memcmp fonksiyonu çağrılacak şuan onun içinde argüman olarak kullanılıcak register ları rahatlıkla okuyabiliriz. Ama bu noktada eklemeyi unuttuğum bir adımı paylaşmak istiyorum. Bizler tarihin ortanca cocukları intel işlemci mimarisine daha alışkınız bu yüzden şuanki arm assembly kodunu okumak biraz tuhaf ve yabancı gelicektir bunu gdb üzerinden rahatlıkla çözebiliriz aynen şu şekilde -> "set disassembly-flavor intel" böylece artık assembly kodu gözümüze çok tanıdık gelicek. İşte final aşamasındayız gördüğünüz gibi rsi ve rdi register larımıza stack üzerinden bazı değerler gönderilmiş ve hiç şüphesiz bunlar memcmp için, hadi bu değerleri okuyalım. "x/s $rsi" komutu ile rdi register ı üzerindeki ifadeyi string tipi olarak okuyabilirsiniz, rsi de bizim az önce girdiğimiz rastgele string ifadeleri var peki rdi de? BUM, bizden istenen bayrak tam olarak burda. Evet şimdi bu uzun paragraf boyunca anlattığım yerlerin önemli gördüğüm kısımlarına ait ekran görüntülerimi sırayla aşağıya yerleştiricem dileyen ordan eksik bir şey yaptıysa veya ilerlemesini kontrol etmek istiyorsa takip edebilir eğer eklememi istediğiniz bir şey varsa yada kafanızı karıştıran, yazmaktan çekinmeyin müsait olduğum sürece büyük bir zevkle sorularınıza yanıt olmaya çalışırım herkese iyi günler, selametle kalın.  
  
  
Sectionlarda gezinip .text in başlangıç adresini buluyorum  

![ng60p43.png](/pictures/tht/ng60p43.png)

  
  
.text in başlangıç adresine breakpoint koyuyorum  

![sdm6hpc.png](/pictures/tht/sdm6hpc.png)

  
  
rip üzerinden instruction ları listeliyorum  

![9x4gb4d.png](/pictures/tht/9x4gb4d.png)

  
  
memcmp fonksiyonun çağrıldığı adresi buldum  

![ll423bn.png](/pictures/tht/ll423bn.png)

  
  
assembly kodunu intel görüntüsüne çeviriyorum  

![pe1mz9k.png](/pictures/tht/pe1mz9k.png)

  
  
rsi ve rdi register larındaki değerleri okuyorum ve flag a ulaşıyorum  

![mw53b0l.png](/pictures/tht/mw53b0l.png)
