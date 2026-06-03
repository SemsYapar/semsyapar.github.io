---
layout: post
title: "PicoCTF - Rolling My Own çözüm denemesi (writeup)"
date: 2022-07-19
source: "https://www.turkhackteam.org/konular/picoctf-rolling-my-own-cozum-denemesi-writeup.2020135/"
---

Selam herkese bugün ılık süt tadında bir CTF daha çözücez umarım keyifli olur. Bu CTF PicoCTF tersine mühendislik kategorisinde 5 sayfadan oluşan soruların 3. sayfasında yer alıyor demek istediğim eğer daha öncesinden tersine mühendislik tecrübeniz yoksa bu CTF sadece vaktinizi alıcak ve kafanızı karıştıracaktır he kafam karışsın istiyorsanız, buyrun gelin. Resimleri deneysel olarak bu seferlik (eğer güzel olursa) sadece linkleriyle paylaşmak istiyorum bunun okumayı kolaylaştırıcağını düşünüyorum çünkü zaten IDA yı kendiniz açmadan bu soruyu sırf benim yazımla anlamanız zor. O yüzden resimlerin ciddli okuyucularımın dikkatini dağıtmalarını istemiyorum.  
  
Önemle Duyrulur:  
NÜTFEN elinize sağlık tarzı mesajlar atarak konumu kirletmeyin. Anlatışımı eleştirin, çözümümü eleştirin, eksik noktalarımı yüzüme vurun, yanlışlarımı belirtin, tavsilerinizi yazın AMA eline sağlık YAZMAYIN konumu okumadan eline sağlık yazınca beni mutlu etmiş olmuyorsunuz aksine hiç SALLANMADIĞIMI düşünüyorum.  
  
  
AÇIKLAMA:  
I don't trust password checkers made by other people, so I wrote my own. It doesn't even need to store the password! If you can crack it I'll give you a flag. remote nc mercury.picoctf.net 11220  
Soru Linki: [https://play.picoctf.org/practice/challenge/151?category=3&page=4](https://play.picoctf.org/practice/challenge/151?category=3&page=4)  
  
Başkalarının şifre kontrol mekanizmalarına güvenmediğini ve kendisininkini yazdığını söylüyor eleman ve bununla bir şifreyi içinde saklamasına bile gerek kalmadığını belirtiyor. Eğer verdiği kodu kırarsak sonda belirttiği sunucudan bayrağı bize vereceğini söylüyor  
Bize verilen kod, çalışan bir sunucunun replikası onu kırıp gerçek sunucudan flaga ulaşmamızı istiyor soru.  
  
ÇÖZÜM:  
Öncelikle main fonksiyonu inceliyelim:  
![n97hhhw.jpg](/pictures/tht/n97hhhw.jpg)
Kendiniz IDA üzerinden bakarsınız daha anlaşılır olur sizin için her adım.  
  
Kodu incelediğimizde strcopy ile değişkene programda daha önceden belirlenmiş bir string atandığını, v11 arrayının indexlerine bazı rakamlar eklendiğini (daha sonra bunların aslında offset olduğunu anlayacağız) fgets ile s değişkenine kullanıcıdan alınan girdinin atandığını görüyoruz. Ardından bir for döngüsü içerisinde dest değişkenine 4 karakter bizim input ve üzerine 8 karakter programın önceden belirlediği rastgele gözüken harflerden atandığını bu 12 lik setin 4 kere devam ettiğini görüyoruz yani şunu anlıyabiliriz burdan bizim girdimiz ne kadar uzun olursa olsun sadece 16 karakteri kullanılıyor program içerisinde...  
Bu setler dest değişkeni üzerinde toplandıktan sonra malloc ile 64 bytelık yer açıyoruz ve bunu ptr pointer ına tutturuyoruz sonra dest in uzunluğunuda v3 değişkenine atıyoruz bunların 3 ünü sub_E3E fonkisyonuna argüman olarak gönderdiğimiz gözüküyor.  
  
Fonksiyonun içine bakalım şimdi:  
![dogoyoe.jpg](/pictures/tht/dogoyoe.jpg)  
Fonksiyonun ilk bölümünde yani if else kısmında içine attığımız dest değişkeninin kaç set (12) ten oluştuğunu belirliyoruz son kısmı 12 karakterden küçükse onu genede bir set olarak sayıyoruz ardından başlıyan for döngüsü içerisinde ise her setin MD5 fonkisyonları aracılığıyla haslendiğini ve hashlenen kısmın (32 bytelık sonuç çıkar md5 hashten giren karakter uzunluğu ne olursa olsun) ilk 16byte ının ptr değişkenine aktarıldığını görüyoruz bunu kaç set varsa yapıyoruz. Aslında programın başında 4 tane bizim girdi 8 de programdan gelen karakterlerin 4 kere ard arda eklenmesi ile oluşturulan dest değişkenininin uzunluğunu kullanarak toplam set sayısını oluşturduğumuz için burda (4+8)*4 ten maksimum 48 karakteri set ediceğimizi bununda 48/12 den 4 set ettiğini tahmin edebiliriz.  
  
Tekrardan main fonksiyona dönelim devam eden süreçte elimizde hashlenmiş dest verisiyle oluşan ptr pointerı var şimdi iç içe for döngüsünde başta oluşturulan v11 değişkenindeki rakamları kullanarak ptr pointerının tuttuğu hashin her 16bytelık bölümündeki (toplam 4 bölüm) başta sözü geçen v11 arrayındaki offsetler kullanılarak 4byte uzunluğundaki kısımlarını v12 pointerının işaret ettiği yerlere kopyalıyoruz en sonunda ise v12 yi v9 a kopyalayıp, v9 içine daha önce görmediğimiz başka bir fonksiyonu argüman olarak atıyoruz.  
  
Argüman olarak kullanılan sub_102B isimli fonksiyonun içine bakarsak bunun bayrak fonksiyonu olduğunu görebiliriz içinde kendisine gönderilen argümanı bir hex sayısı ile karşılaştıran ve eğer doğru ise bayrağımızın olduğu dosyayı ekrana bastıran bir kodlar silsilesi var.  
Bayrak fonksiyonunun ekran görüntüsü: ![tojof00.jpg](/pictures/tht/tojof00.jpg)  
  
Peki bu algoritmayı nasıl kendi lehimize çevirebiliriz. Olay örgüsünü toparlayacak olursak. Girdimiz önce programın içinde daha önce belirtilen bir string bölümüyle 4 bizden 8 ondan olmak üzere birleştiriliyor ardından  her 12 lik set (son setse 12 den daha küçükte olabilir) hasleniyor, oluşan hashlerin 16bytelık ilk bölümü alınıyor ve hashlenmiş stringin her 16byte bölümüne özel bazı bölümlerini v11 offsetleriyle yakalayıp bir pointera sırayla diziyoruz sonra bu pointer ı bir fonksiyon gibi kullanarak içine başka bir fonksiyonu parametre olarak atiyoruz. Eğer pointer ımızın içine argüman olarak attığımız bu fonksiyona kendisine argüman olarak gönderilen sayı, içinde kontrol edilen sayıya eşitse server bize bayrağı veriyor. Şuana kadar vermedi tabi. Enazından bize...  
  
v9 pointer ın fonksiyon olarak kullanılması size tuhaf gelebilir, bana da gelmişti daha önce hiç karşılaşmadığım bir durum. Ama assembly yansımasını görürseniz belki kafanızda bir yere oturabilir. Ve -HEEEEğğğğeeeeHğ diyebilirsiniz.  
Kolay yoldan decompile edilen kod parçacığının her bir satırını assembly üzerinden takip etmek için IDA da kodun üstüne sağ tık yapıp senkron seçeneğini işaretlemeniz gerekiyor daha sonra assembly sayfasına gidince c kodunda bastığınız satırın assembly yansımasını orda üzeri boyalı olarak görüceksiniz.  
Tam olarak v9(sub_102B); satırı assembly de şu şekilde gözükmekte...  
mov     rax, [rbp+var_F0]  
lea     rdi, sub_102B  
call    rax  
  
rax register ına v9 pointer ımızın işaret ettiği seçilerek toplanan hashden dönme veri atılıyor sonra rdi register ına da bayrak fonksiyonumuz atılıyor ardından rax çağrılıyor. Bu noktada şunu anlıyabilirsiniz. Rastgele girdilerimizde program büyük çoğunlukla segmentation hatası vericektir sebep rax ın tam olarak çağrılıcak bir fonksiyon yapısına sahip olamaması bu yüzden açıklama kısmında adam programının bir şifreyi saklamasına bile gerek olmadığını söylemiş çünkü gerek tek şey doğru şekilde çağrılıcak rax fonksiyonunu oluşturucak girdiyi üretmek.  
  
Bunun için bir bruteforce scripti yazmamız lazım bissürü deneme yaparak uygun shellcode u bizim için oluşturucak. İşte:  

```python
import hashlib

girdiye_eklenen = ["GpLaMjEW", "pVOjnnmk", "RGiledp6", "Mvcezxls"]
shellcode = ["4889fe48", "bff126dc", "b3070000", "00ffd6"]
offset = [8, 2, 7, 1]
sifre = ""
for i in range(0, len(girdiye_eklenen), 1):
    evraka = False
    for c1 in range(32, 127, 1):
        for c2 in range(32, 127, 1):
            for c3 in range(32, 127, 1):
                for c4 in range(32, 127, 1):
                    girdi = chr(c1)+chr(c2)+chr(c3)+chr(c4)
                    hashlenicek = girdi + girdiye_eklenen[i]
                    hashlendi = hashlib.md5(hashlenicek.encode()).hexdigest()
                    if hashlendi[offset[i]*2:offset[i]*2+len(shellcode[i])] == shellcode[i]:
                        sifre += girdi
                        print("girdinin bir parçasını buldum! -> " + girdi)
                        evraka = True
                        break
                if evraka:
                    break
            if evraka:
                break
        if evraka:
            break
print(sifre)
```

  
Kısaca açıklamak gerekirse programın bizim girdimize eklediği stringleri 4 e böldüm çünkü hatırlayacağınız gibi 4 parçalı bir hashleme seansımız olucak her parçanın kendi özel offseti var yukarda bunu açıklamaya çalışmıştım bu parçaları teker teker ele alıcaz yani mottomuz "parçala ve fethet" olucak.  
  
KAPANIŞ:  
Anlayamadığınız bir nokta olursak en ufak bile olsa yazmaktan çekinmeyin bundan rahatsız olmam aksine beni onure edersiniz. Bana verebileceğiniz en büyük tebrik mesaj bu olur. Önceki CTF çözümlerime profilimden ulaşabilirsiniz, tabi isterseniz. Hayırlı geceler, esenlikte olun.
