---
layout: post
title: "PicoCTF format-string-2 sorusu çözümü (%n format specifier ı nedir ne işe yarar)"
date: 2024-07-05
source: "https://www.turkhackteam.org/konular/picoctf-format-string-2-sorusu-cozumu-n-format-specifier-i-nedir-ne-ise-yarar.2061729/"
---

CTF lerde PWN diye de geçen Binary Exploitation alanındaki PicoCTF sorularını çözerken format string zaafiyeti barındıran birkaç soru ile karşılaştım ve bu soruları çözebilmek için öğrenmem gereken şeyleri ararken %n specifier ı hakkında hiç türkçe kaynak olmadığını fark ettim. Şimdi ve sonra bu olayı öğrenmek isteyen arkadaşlara türkçe bir kaynak olması için bu konuyu açıyorum.  
  
Öncelikle bu format string dediğimiz şey ne buna değinelim. Hemen hemen her dilde stringlerin içine değişkenler ekleme gereği duyarız bunu kolayca halletmemiz için kullanılan yapılardır. C üzerinden gidicek olursak printf fonksiyonu ilk parametre olarak bir format string alır. Aynı normal bir string dir aslında tek farkı işlenme biçimidir. Bir format string yazarken format specifier lar kullanılır. Format specifier lar ikinci, üçüncü, dördüncü artık ne kadar varsa özel olarak hangi parametreyi alacakları belirtilmemişse sırasıyla parametreleri alıp kendileri ne tipse veriyi o tipe dönüştürürler ve bu sayede değişkenlerimizi eklediğimiz string imizi oluşturuz. printf bunu stdout a aktarır genel kullanımda ve sonuç olarak string kullanıcıya gösterilmiş olur. Format specifier kullanarak çalışan C dilinde daha çok sayıda fonksiyon vardır. Bazısı bu format specifier lar ile oluşturulan metni printf gibi ekrana bastırır bazısı başka bir değişkene aktarır başkası alır uzaya fırlatır böyle uzar gider. Ama bizim için ortak nokta hepsinin format string yapısını işleme kabiliyetine sahip olmasıdır peki format string zaafiyeti ne zaman patlak verir?  
  
#include <stdio.h>  
  
int main(int argc, char **argv) {  
    char buf[60];  
    fgets(buf, 60, stdin);  
    printf("%s soldaki bir format specifier bense bir format string im.", buf);  
}  
  
  
Yukaridaki kodda kullanıcıdan max 60 karakter olacak şekilde bir veri alıyoruz sonrada bunu printf imizin ikinci parametresine yerleştiriyoruz format string imizdeki format specifier (%s) aldığı veriyi string olarak yorumlar ve sonuç olarak printf buf değişkenindeki string in sonundaki null karakter e (\x00) kadar okuma yapar ve sonucu format string de %s yazan kısmın yerine yazar.  
Peki şu şekilde yapsaydık:  
  
#include <stdio.h>  
  
int main(int argc, char **argv) {  
    char buf[60];  
    fgets(buf, 60, stdin);  
    printf(buf);  
    printf("soldaki bir format specifier bense bir format string im.");  
}  
  
bu iki program ortalama bir kullanıcı için aynı çıktıyı verir ama format string zaafiyeti hakkında az çok fikir olan biri format string olarak direk kullanıcı girdisinin koyulmaması gerektiğini bilir, peki neden?  
  
aşadaki kodda kullanıcı girdisi format string olarak yorumlanır bu da kullanıcının girdi olarak herhangi bir format specifier yazdığı anda bunun printf tarafından "A bakın işlemem gereken bir format specifier hemen ikinci parametredeki değeri buna aktarıyım" şeklinde yorumlanır. "Ama ikinci parametre yooook??!" diyebilirsiniz.D Aslında var. Sizin için olmayabilir ama işlemci için var. Örnek olarak zaafiyetli ikinci kodu çalıştırdığımızı ve girdi olarak "%x" girdiğimizi varsayalım. Bu format specifier normalde printf e verilen ikinci parametredeki değişkenin ilk 4 byte ını hexadecimal olarak yorumlamaya yarardı lakin şuan printf in ikinci parametresi yok o zaman ne vericez biz %x imize? Aslında bu mimariye bağlı, eğer 32 bit bir programla uğraşıyorsak orda olan şey kesinlikle printf fonksiyonu çalışmadan önce stack te olan ikinci 4 byte (ilki format string in adresidir). Eğer 64 bit bir programsa o zaman %x in tutucağı değer rsi registeri (tabi register ın yarısını tutabilir çünkü %x sadece 4 byte lık bir tutucudur eğer rsi nin tamamını almak istiyorsak girdimizi %lx yapabiliriz l nin anlamı long ve bu sayede artık 8 byte ı birden görebiliriz) olacaktır (64 bit sistemlerde format specifier ların art arda tuttukları ilk 5 değer bazı registerlara tekabül eder onlarda şunlardır: rsi, rdx, rcx, r8, r9).  
  
Yani değişkenlerimiz yoksa adresler var ve bu adreslerde programımız için hassas bilgiler olabilir. Mesela ne olabilir. Kullanıcıların erişmesini istemediğimiz bir değişken; stack canary, sevgilimize mektup falan filan. Sonuç olarak process memory sinin belirli bir bölgesinin okunması kimsenin hoşuna gitmez, gitmez dimi?  
  
Evet şuana kadarki kısım kabaca format string zaafiyetini kısaca tanıma ve bunu kabaca printf fonksiyonu üzerinden gösterme şeklindeydi ve zaafiyetin sadece "veri okuma" kısmına değindik. "E başka ne yapılır hacı bunla" dicek olabilirsiniz ki bende öyle düşünüyordum ta ki format string zaafiyeti ile veri yazılabileceğini öğrenene kadar! Hassssss falan oldunuz dimi. Evet aşkolar bu zaafiyet ile veri de yazabiliyoruz.  

<iframe width="560" height="315" src="https://www.youtube.com/embed/9sOhO2UCTW4" frameborder="0" allowfullscreen></iframe>

  
Peki bunu nasıl yapıyoruz? Aslında şuana kadar kısmı hiç yazmadan direk burdan başlıcaktım sonra üst kısmada "bu konuyu şunları şunları bilmiyorsan okuma" tarzı bişey yazıcaktım sonra bunun çok zalimce olduğunu düşündüm enazından format string zaafiyeti ne bilmeyen ama çıtırından assembly, tersine mühendislik, işlemci mimarisi ve en önemlisi işlemci assembly dili ilişkisini bilen birinide kazanmak amacıyla böyle bir giriş yaptım. Gözün yorulmadıysa devam et yorulduysa yarın gel burdan devam et okumaya, ne yaparsan yap. Şimdi asıl mevzuya giriyoruz:  
  
[https://play.picoctf.org/practice/challenge/448?category=6&page=2](https://play.picoctf.org/practice/challenge/448?category=6&page=2) format-string-2 adlı sorumuza bu linkten ulaşabilirsiniz eğer aktif bir okuma yapmak istiyorsanız aynı sitede format-string-1 i çözüp öyle gelin, o soru veri okuma ile ilgili çünkü anlattığım şeyin pratiğini yapmış olursunuz.  
  
format-string-2 sorusunda bir kaynak kod bir binary bide netcat bağlantısı verilmiş. Basit PWN soruları bu şekilde işler genellikle kaynak kodu okursunuz, binary üzerinde keşif yapıp payload ınızı hazırlarsınız sonrada payload ile netcat bağlantısının diğer ucundanki binary nin canlı halini patlatır flag ınızı alırsınız.  
  
kaynak kod:  

```c
#include <stdio.h>

int sus = 0x21737573; #sus isminde bir değişken var içine de hexadecimal şeklinde bir veri koyulmuş

int main() {
  char buf[1024];
  char flag[64];

  printf("You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n");#adam diyo nasıl yapcan diyo olmaz diyo
  fflush(stdout);
  scanf("%1024s", buf);#bizden çekilen veri 1024 karakterle sınırlandırılmış daha fazlasını iteleyemiyeceğiz buf değişkenine buda buffer overflow dışında bir şık üzerine düşünmemiz gerektiği anlamına geliyor
  printf("Here's your input: ");
  printf(buf);#Hass*komen bunu yukardaki zaafiyetli kodumuzdan hatırlıyorsunuz değil mi
  printf("\n");
  fflush(stdout);

  if (sus == 0x67616c66) {#sus değişkeninin kontrol edildiğini görüyoruz ama ilk başta tanımlanan değerden daha farklı bir değer olarak, e biz bunu nasıl değiştiricez??
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");

    // Read in the flag
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);

    printf("%s", flag);#doğru şekilde değiştirdiğimiz takdirde flag.txt okunuyor ve flag ımız bize veriliyor
    fflush(stdout);
  }
  else {
    printf("sus = 0x%x\n", sus);
    printf("You can do better!\n");#yaprağı aldın diyor
    fflush(stdout);
  }

  return 0;
}
```

  
kodda açıklama satırlarında olayı yeterince iyi açıkladığımı düşünüyorum şimdi bunu nasıl yapacağımızı düşünelim.  
Size sırf format string zaafiyeti ile veri yazabilmemiz için bir format specifier tasarlamışlar desem? Evet gerçekten böyle bir şey var kendisi -> %n  
Bu arkadaş diğer specifier lardan biraz daha farklı çalışıyor çalışma mantığı şöyle:  
"In C printf(), %n is a special format specifier which instead of printing something causes printf() to load the variable pointed by the corresponding argument with a value equal to the number of characters that have been printed by printf() before the occurrence of %n."  

![ssroq11.jpg](/pictures/tht/ssroq11.jpg)

  
Ne saçma dimi? Burdan tüm C/C++ ile kod yazanlara sesleniyorum hayatınızda böyle bir şey gördünüz mü? Çoğu yerde hiçbir şey yapmaz, boşverin, sallayın diye geçen bir specifier bu işte ama pwn cilerin can kaynağı. Basitçe kendisinden önce kaç karakter yazıldıysa bunu belirtilen parametreye yüklüyor. Size şöyle basit bir örnek vereyim:  
#include <stdio.h>  
  
int main(int argc, char **argv) {  
    int has = 0;  
    printf("Ses kes%n\n", &has);  
    printf("%%n den onceki metin %d karakter uzunluğunda", has);  
}  
"Ses kes" string i 7 karakter uzunluğunda bitişinde gelen %n bu karakter uzunluğunu yani 7 yi has değişkenine yüklüyor yani has ın yeni değeri 7 oluyor.  
  
  
Peki orda %n in karakter uzunluğunu yükleyeceği bir parametre olmazsa?  

<iframe width="560" height="315" src="https://www.youtube.com/embed/FsT2HqrO5PM" frameborder="0" allowfullscreen></iframe>

  
Böyle bir durumda nasıl az önce o adreste ne varsa onu bastırıyorsak (%x) şimdide o adres gerçektende bir yeri işaret ediyorsa yani bir pointer sa işaret ettiği yere verimizi yazacağız. Burda bir pointer ile çalışıyor olmamız gerekiyor yukardaki iki örnekte de gördüğünz gibi değişkenlerin hep adreslerini veriyoruz parametre olarak yani %n specifier ı pointer kullanarak işlem yapıyor dikkat etmemiz gereken ilk şey bu. Eğer %n in yükleme yapmaya çalıştığı adres gerçekte yazılabilir bir yeri işaret etmiyorsa segmentation error alacağız ve program kapanıcak.  
  
Sorumuzda zaafiyetli satırmız "printf(buf);". buf u direk biz oluşturuyoruz burdada onu print ediyoruz, bir şekilde %n specifier ını da kullanarak sus değişkeninin overwrite etmemiz ve oraya "0x67616c66" sayısını yazmamız lazım. Bu noktada şuana kadar her şeyi anladıysanız kafanızda oluşabilecek tek soru veriyi nereye yazacağımızı nasıl bileceğimiz olacaktır. Veriyi nasıl oluşturacağımızı biliyoruz 0x67616c66 sayısı kadar karakter yazıp ardından %n koymak bu şekilde karakter uzunluğumuz alınıcak ama nereye yüklenecek işte esas mesela yükleyeceğimiz yerde "sus" değişkeninin olmasını sağlamak. Bunu yapmak için iki aşamalı bir planımız var birincisi stack te istediğimiz şekilde dolanma özgürlüğü ikincisi ise bu özgürlüğümüzü kullanarak sus değişkeninin adresini işaret etmek. Birincisi için format specifier ların size daha önce söylemediğimiz başka bir özelliğini daha göstereceğim.  
Önce legal kullanımına bir örnek kod vereyim:  
  
#include <stdio.h>  
  
int main(int argc, char **argv) {  
const char* a = "cafer";  
const char* b = "benim adim";  
printf("%2$s %1$s", a, b);  
  
}  
  
Bu kodda format string in önce printf in 3. parametresini sonrada 2. parametresini almasını sağladık spesifik olarak hangi format specifier ın hangi değişkeni alacağını belirleyerek. Aynısını zaafiyetli kodumuzda yaptığımızda bu bize stack te yahut register larda gezinme imkanı verecek.  
Bu özelliği denemek için en başta verdiğim iki koddan ikincisi yani zaafiyetli olanını derleyip kullanabilirsiniz. Ben o programı kullanarak örneklendiriceğim anlatıcağımı. Eğer kodumuzu 32 bir olmak üzere derlersek ve programımızı çalıştırıp bir tane %x girdisi verirsek ne olacağını yukarda anlattım peki iki tane koyarsak?  

![fkwtzzg.png](/pictures/tht/fkwtzzg.png)

  
Pek şaşırtmayacak ve gayet doğal bir şekilde stack teki bir sonraki 4 byte ımızın bastırıldığını görüyoruz. Bu bu şekilde stack in sonuna kadar gider. Ama eğer 10 değeri istiyorsak lakin öncesinde 9 tane %x koymak istemiyorsak ne yapabiliriz. Sevgili C geliştiricileri bizi düşünmüş ve format specifier ımızı şu şekilde de yazabilmemize imkan vermişler:  

![eqc1ii3.png](/pictures/tht/eqc1ii3.png)

  
Bakin bu örnekte stack teki ikinci 4byte ı direk çektik bunu %n$x yapısını kullanarak yaptık x in olduğu kısma diğer format specifier ları da yerleştirebilirsiniz n yazan kısmada kaçıncı değeri çekmek istiyorsanız ona göre yazıyorsunuz. Resmen pwn yapalım diye getirilmiş güzel bir özellik daha  
Bunu %n e uygulayabiliriz ve istediğimiz yeri işaret edebiliriz tabi o yerde hala "sus" değişkeninin olup olmadığı malum. Bunu nasıl halledecez peki? Yani "sus" değişkeninin adresini nasıl bulucaz. Arkadaşlar Demokraside çareler tükenmez. Şimdi size süper bir fikir vereceğim. Eğerki biz tam olarak "buf" umuzun yani girdimizin içeriğinin stack te nerde tutulduğunu bulursak? Eğer bunu yaparsak oraya buf da ne varsa o yazıldığı için oraya sorudaki "sus" değişkeninin adresini yazabiliriz ve %n specifier ımızı da az önce öğrendiğimiz index seçme yöntemini kullanarak stack teki girdimizin olduğu yere yükleme yapmasını sağlayabiliriz. Girdimizin içeriği "sus" değişkeninin adresi olucak ve %n den önce ne kadar uzunlukta bir string imiz varsa bu değer "sus" adresinin işaret ettiği yere yazılacak! Böyle anlatınca karmaşık gelmiş olabilir hadi bir deneme yapalım. Denemeleri yapmak için sorunun verdiği elf binary sini kullanacağım.  
Önce "sus" değişkeninin adresini bulmak için gdb yi açıyorum main fonksiyonu inceliyorum: (Başka sorularda bu şekilde hiç değişmeyen bir adres bulamayabiliyoruz, ASLR aktif ise)  

![ge35l28.png](/pictures/tht/ge35l28.png)

  
kırmızı şekilde işaretlediğim kısım "sus" değişkeninin tutulduğu adres, "sus" adresten alınıp eax a veriliyor sonra eax "sus" ta olmasını istediğimiz değer ile karşılaştırılıyor eğer aynı iseler bayrağımız bastırılıcak şuan aynı değiller.  
  
adresimizi gdb yardımıyla buluyoruz:  

![3v1yz20.png](/pictures/tht/3v1yz20.png)

  
İşaretlediğim kısım "sus" değişkeninin adresi, yukarıya eax ı da koydum o anki, meraklısına  
Peki girdimizin "buf" umuzun kendisi hangi adreste? bunu da gene gdb yardımıyla bulacağız. Aslinda gdb ile uğraşmadan bruteforce layada biliriz yani arttıra arttıra %1$x den başlayıp %20$x e kadar yazarız mesela ilk 20 değerden hangisi hex ten text e dönüştürülünce bizim girdimiz ise o sayıyı kullanarak devam da edebiliriz ve böylece doğru index in %14$x olduğunu anlarız ama bunun mantığını göstermek adına hesaplamalı yöntemi de göstereceğim. Zaafiyetli printf e breakpoint koyuyorum ve programı çalıştırıyorum sonrada printf im çalışmadan hemen önceki stack imin görüntüsüne bakıyorum:  

![6bsu738.png](/pictures/tht/6bsu738.png)

  
breakpoint koyacağım printf in yeri main de burası  
  

![mfwpy6m.png](/pictures/tht/mfwpy6m.png)

  
İki tane yerin altını çizdim. sağda scanf ile verdiğim girdi yi görebilirsiniz 3 karakter uzunluğunda, solda ise bu verinin adresi. Aslında şimdi düşündüm de "buf" umuzun adresi ile işimiz yok stack te kaçıncı yerde onun bilgisi lazım yani ikinci kırmızı çiziği s* edin. Hadi sayalım. rsp deki ilk 10 veriyi çıkartırken xg yazmışım ordaki x hexadecimal çıktı ver demek g ise giant g yi yazma sebebim çıktıyı 8 byte lık paketler halinde almak nede olsa 64 bit mimari ile uğraşıyoruz bu yüzden stack deki her bir değer 8 byte o halde sayalım adresler yukardan aşağı, soldan sağa artıyor stack te altlara iniyoruz, o halde bizim stack teki yerimiz 9 numara.  
  
Artık "sus" değişkeninin adresini ve buf umuzun stack te kaçıncı yere yazıldığını öğrendik şimdi bu bilgileri kullanarak deneme payload umuzu oluşturalım:  
Little Endian bir yapıya sahip programla çalıştığımızdan (Çoğunlukla her şey Little Endian yapıdadır) adresi tersten başlayarak yazmamız gerekiyor sebebini burda açıklamayacağım konumuz dışı  

![p1bo8m9.png](/pictures/tht/p1bo8m9.png)

  
Payload sayesinde fark ettiyseniz "sus" değişkenimizin değeri 0 oldu. Peki nasıl oldu gelin payload umuzu açıklayalım.  
"%15$n" ifadesi stack teki 9. değeri %n format specifier ına vermemizi sağladı 'e neden "%9$n" yazmadık' dicek olursanız tekrardan 64 bit mimariye sahip programda çalıştığımızı ve yukarlarda bahsettiğim gibi 64 bit mimaride format specifier ların tuttuğu ilk 5 değerin bazı register lar olduğunu hatırlatmam gerekicek. Yani 5+9 den stack teki 9. değere ulaşmak için 14 yazmamız gerekiyor ama biz 15 yazmışız. Hoppa! İkinci fake, neden öyle yaptık. Şöyleki "buf" umuz stack teki yerine yazılırken kendisi büyük olduğu için sadece 8 byte olmadığı için stack teki bir sonraki kısmıda doldurdu payload da gördüğünüz gibi %n için gerekli adresi de sona yazdığım için ilk sekiz değil son sekiz byte ı %n e vermemiz gerekti bu yüzden stack de bir adım daha atıp 10. değeri işaretlemek için 14+1 den 15 yazmamız gerekti. Bu yüzden arada 3 tane daha bomboş büyük "A" var. ilk sekiz byte ı doldurup diğer stack in sekiz byte ını istediğimiz şekilde sadece adresle doldurmak için padding yapmış olduk "A" yerleştirerek. Payload ı sayıcak olursanız tamı tamına 16 karakter olduğunu görürsünüz. %n imizin 10. stack e baktığında sadece veriyi yükleyeceği adresi görmesi için bu şekilde yapmamız gerekiyor. %n e adresin birazı 9. stack e sarktı birazı 10. ya sarktı diyemeyiz. Kapiş. Anlamadıysan aç gdb yi biraz bak stack e birkaç payload hazırlayıp deneme yap daha iyi oturur. Peki "sus" adresimize ne yazıcaz? Gördüğünüz gibi %n specifier ımız dan önce hiçbir şey olmadığı için 0 yazmış olucaz.  
  
Bide değinmek istediğim bir nokta var. Az önce size adresi sona yazdığımı söyledim aslında bu kasıtlı ve zorunlu bir işlem çünkü adresi başa yazarsam eğer printf null (\x00) karakterleri görür görmez kapanıcak. yani %n specifier ımız çalışamayacak. Bu yüzden adresi sona yazdım. gene printf payload ımızı bastırmak istediğinde ilk null karakteri gördüğünde durucak ama o zamana kadar biz %n specifier ımızı çalıştırtıp adresimize 0 yazmış olacaz.  
  
Tabi soruyu hala bitirmedik. Soru bizden 0 değil 0x67616c66 yazmamızı istiyor "sus" a. E duruyoruz dimi hemen 0x67616c66 yani 1734437990 tane karakter yazalım %n den önce o da onu yazsın! Dur evlat öyle şey olur mu. printf ın o kadar karakteri bastırmasını bekleyene kadar güneş patlar a*. Öyle hopadanak yazmayacağız. Parça parça "sus" değişkenini değiştiricez. Hadi 2 byte 2 byte yapalım.  
Normalde %n specifier ı dümdüz kullanırsak 4 byte lık yükleme yapar. Ama eğer başına bir "h" eklersek ki "h" short demek yani short n bu shortlukta bize 2 byte lık bir yükleme sağlıyor eğer tek byte yükleme yapmak isteseydik bir "h" daha eklerdik. Ama bu durumda bir "h" kafi. Gelin bunu kullanarak bir deneme payload daha yazalım, öncekinin aynısı tek farkı short n kullanımı olucak ve padding i değiştiricez tabi uzunluk değiştiği için.  

![4bsjunl.png](/pictures/tht/4bsjunl.png)

  
h ekledim n nin başına bitane "A" yıda çıkardım yani gene 8+8 görüntüsünü yakaladım adres gene 10. stack te.  
Gördüğünüz gibi busefer "sus" değişkenimizin ilk 2 byte ı sıfır oldu sadece çünkü 2 bytelık bir yükleme yaptık az önce 4 byte ınıda sıfırlamıştık.  
Tamam şimdi sorunun bizden istediği sayıyı oluşturucaz ilk iki byte ımız  0x6c66 bunu 10 luk sisteme çeviricek olursak 27750 yi elde ediyoruz. Son iki byte ımız ise 0x6761 bu ise 10 luk sistemde 26465 yapıyor. Şimdi burda şöyle bir durum var ben ilk başta 27750 tane karakter yazıp sonra da "sus" değişkeninin ilk iki byte ını değiştirirsem sonra g*tümü yırtsam son iki byte ı istediğim şey yapamam çünkü onlar için gereken karakter sayısı daha az bu yüzden ilk son iki byte ı değiştiricem. Bunu yapmak için yani son iki byte i değiştirmek için "sus" değişkenimi işaret eden pointer ımı iki byte kaydırmalıyım. Payload ı göstereyim bu dediklerimi ve daha fazlasını onu görerek okuyun yoksa iyice kompleks gelecek.  

![rgvz4m7.png](/pictures/tht/rgvz4m7.png)

  
Kafalarda karışma olmasın diye tam boy büyültüm ss aldım. Burda adım adım payload umuzu inceleyelim:  
Baştaki "%26464x" kısmı yabancı geldi çünkü onu daha önce hiç göstermedim. tutup 26464 tane karakter yazacağımı yada kopyala yapıştır yapacağımı düşünmüş olabilirsiniz. Ne iyiki C gelişitiricileri biz pwn cilerin işini kolaylaştırmak için bir özellik daha eklemiş buna padding yapmak deniyor olayıda 26464 tane space atmak, harbiden bu işe yarıyor sadece.  
sonra artık aşina olduğumuz spesifik bir yer seçen format specifier ımızı görüyoruz "%18$hn" 5+9+4 şeklinde, sondaki 4, payload un sonunda bulunan adreslerden ilk adrese kadar toplam 4 byte karakter olduğu için eklendi +5 register lari geçmek için +9 da stackte buf muzun başlangıcına gitmek içindi +4 lede buf un üzerinde ilerlemiş olduk bu sayede ilk adresin işaret ettiği yere %n specifier ımız kendisinden önceki karakter sayısını kaydediyoruz buda 26465, hexadecimal olarak 0x6761. Gördüğünüz üzere kullandığımız adres 0x404060 değil 0x404062 çünkü son iki byte ı değiştirmek istedik ilk hetapda bir nevi onların toplamı daha az ettiği için zorunda kaldık. Payload un geri kalanında da gene bir padding var "%1285x" yani 1285 tane space atıyoruz değil mi peki şuana kadar attığımız space lerle toplayınca kaç ediyor 26464+1285 -> 27749 hexadecimal olarak 0x6c65 vaay yani ilk iki byte için gereken karakter sayısına böylece ulaşmış olduk ve şimdide son hamle "%19$hn" bu arkadaş a payload umuzun son kısmındaki 8 byte a ulaşmak için 5+9+5 ten 19 yazdık bu sayede ordaki adrese yani 0x404060 e de ilk iki byte ımızı yüklemiş olduk. padding ler yüzünden sonuç gözükmüyor şöyle biraz daha alta çekeyim barı sonuç u da görün.  

![en9w7m1.png](/pictures/tht/en9w7m1.png)

  
bayrak yerine 31 ler karşılıyor bizi, çünkü bu binary bozuk çıktı vermesin diye Desktop dizinimde içinde 31 ler yazan bir flag.txt im var.  
Tamam orjinal binary ye bu payload larımızı gönderelim netcat adresi sayesinde bakalım.  
  

![ngzp52t.png](/pictures/tht/ngzp52t.png)

  
Vee sonuç:  

![ji9lalw.png](/pictures/tht/ji9lalw.png)

  
  
Evet aslında bura bitiyor ama size son bir şey daha göstermek istiyorum. Bu konuda format string zaafiyeti ile %n specifier sağolsun. stack e veri yazmayı gördük ama bu işlemi pwntools sayesinde çok daha kolay yapabiliriz. Manuel yapım dışında bu tool ilede payload oluşturrayım size bunun için mini bir python kodu yazalım hemencicik:  

```python
from pwn import *

context.bits = 64
payload = fmtstr_payload(14, {0x404060:0x67616c66})
print(payload)
```

fmtstr_payload fonkisyonunun ilk parametresi printf in yada herhangi bir format string kullanan fonksiyonun çalışmadan hemen önce stack te tuttuğu buf değerimizin index i, 64 bit programda çalıştığımız için 5 registerlar 9 da stack te kaçıncı olduğumuzdan 14, ikinci parametre ise bir dic; key kısmına değiştirmek istediğimiz değişkenin adresi, value kısmına yeni değeri yazıyoruz. Sonuç böyle:  
b'%102c%20$llnc%21$hhn%5c%22$hhn%245c%23$hhnaaaaba`@@\x00\x00\x00\x00\x00c@@\x00\x00\x00\x00\x00a@@\x00\x00\x00\x00\x00b@@\x00\x00\x00\x00\x00'  
bunuda yapıştırırsak programa  

![nmdqma2.png](/pictures/tht/nmdqma2.png)

  
Aynı şekilde 31 lerimize kavuşuyoruz. Gördüğünüz gibi sonuç için iki saat aşağı inmemiz gerekmedi çünkü pwntools un hazırladığı payload byte byte yükleme yapıyor buda yüklenen karakter sayısının toplamda çok daha az olması buda az padding demek. Byte byte yükleme yaptığı için de son kısımda 2 değil 4 adres görüyorsunuz.  
  
Kafanıza takılan bir şey varsa yazabilirsiniz. PicoCTF bu işi öğrenmek için güzel bir başlangıç yolu size de tavsiye ederim. Selametle kalın.  
  
NOT: yazım yanlışları ve cidden hatalı ifadeler yazmış olabilirim yazmam baya uzun sürdü sonuna geldim başını unuttum resmen o yüzden buna hazırlıklı olun eğer lan ne alaka ya dediğiniz bir ifade varsa hemen yazın konunun altına düzenlenir.
