---
layout: post
title: "reverse_cipher - Crackme - basit düzey"
date: 2022-07-27
source: "https://www.turkhackteam.org/konular/reverse_cipher-crackme-basit-duzey.2020600/"
---

Selamlar CTF çözmenin zamanı yoktur şuan her ne yapıyorsanız size şunu söyliyebilirim ki birazdan çözüceğiniz CTF gerçekten hoş hoşunuza gidecek.  
  
CTF Linki => [https://play.picoctf.org/practice/challenge/79?category=3&page=3](https://play.picoctf.org/practice/challenge/79?category=3&page=3)  
  
AÇIKLAMA:  
We have recovered a [binary](https://jupiter.challenges.picoctf.org/static/31c9b832d036a10daeef52d8b4290ef0/rev) and a [text file](https://jupiter.challenges.picoctf.org/static/31c9b832d036a10daeef52d8b4290ef0/rev_this). Can you reverse the flag.  
  
Bize bir elf çalıştırılabilir dosyası ve metin dosyası veriyor.  
  
Metin dosyasının içinde büyük ihtimal şu halde bayrağımız olamıyacak gibi gözüken bozulmuş bir bayrak var işte böyle:  
picoCTF{w1{1wq85jc=2i0<}  
  
Hadi çalıştırılabilir dosyamıza bir göz atalım:  
  
IDA ile dosyamı açıyorum ve main fonksiyonumu buluyorum ilk satırları işte burda:  

![ahc6r5f.png](/pictures/tht/ahc6r5f.png)

  
Gördüğünüz gibi iki okuma işlemi çalışıyor program birincisi flag.txt adında, ikincisi rev_this adında bir dosya  
  

![ishgi01.png](/pictures/tht/ishgi01.png)

  
Varlıkları kontrol ediliyor duruma göre hata mesajı atılıyor.  
  

![9n73y6j.png](/pictures/tht/9n73y6j.png)

  
Burda dosya flag.txt dosyasının pointerı kullanılarak dosyadan 18h yani 24 karakterlik bir veri okunuyor bu veri ptr pointerına tutturuluyor, fread fonkisyonundan okunan boyut döner bu boyut ilk başta fonksiyona argüman olarak gönderilen size değerinden büyük veya küçükse bir hata var demektir yada dosyanın sonuna ulaşılmıştır. Bizim durumumuzda bu değerin 0 dan büyük olup olmadığı kontrol ediliyor eğer büyükse devam, değilse nanay program sonlandırılıyor.  
  

![90snjb5.png](/pictures/tht/90snjb5.png)

  
Bir döngüye bakıyorsunuz. rbp+var_8 in gösterdiği değer 7 olana kadar döngü devam ediyor her tur değerimiz 1 arttırılıyor. Bu süreçte flag.txt dosyasının okunan değerini tutan ptr pointerımızın ilk 8 harfi rev_this dosyamızı tutan pointer kullanılarak rev_this dosyasına aktarılıyor. konsepte biraz aşinasanız bunun bayrağın şifrelenmemiş ilk 8 karakteri olan "picoCTF{" olduğunu anlayabilirsiniz.  
Değerimiz 7 den büyük olduğu an döngüden çıkıyor ve 8 değerine eşitleniyor ardından bir döngüye daha giriyoruz.  

![aeshcbd.png](/pictures/tht/aeshcbd.png)

  
İkinci döngümüzde değerimizin 16h yani 22 karakter olup olmadığının kontrol edildiğini görebilirsiniz. Ardından gene aynı işlemler yapılıyor ptr nin tuttuğu flag.txt nin 9. karakterden başlıyarak bütün karakterleri tek tek rev_this dosyamızı tutan pointer kullanılarak rev_this dosyasına aktarılıyor. AMA bir ara segment var bir if bloğu gözüküyor ve durum farklılıklarına bağlı olarak o anki harf eax register ına verilerek register ımıza 5 ekleniyor veya 2 çıkarılıyor ve sonuç o anki harf ile değiştiriliyor. Peki neye göre harfimizden 5 ekliyor veya 2 çıkarıyoruz. Bunun için kontrol aşamasına bakmanızı istiyorum. Ne görüyorsunuz. Size söyliyeyim, harfimiz eax register ına veriliyor ve eax register ı and operatörüyle münasabete giriyor bu sonuç eğer sıfır ise harfimiz 5 eklenen yola eğer değilse 2 çıkarılan yola giriliyor. And operatörü bitwise bir operatördür tabi bu pythonic bir tabir oldu assembly okuması yaptığımızdan burdaki operatörlerin hepsi zaten bit düzeyinde işlem yapar.  
And operatörü kendisine verilen iki değerin bit hallerini alır ki burda bir karakterle bir rakamı karşılaştırdığımız için bu 1byte eder 1byte 8 bit olduğuna göre 8 tane bit sırayla karşılaştırılıcak demektir bu, bu şöyle olur mesela ilk bitlerin 0 olduğunu düşünelim 0 ve 0  karşılaştırılır ikiside 0 olduğu için sonuç 0 olur bu sonuç and operatörünün ilk argümanı neyse ona aktarılır bu durumda eax a aktarılıcak sonra ikinci bite geçilir 0 ve 1 lerin karşılaştığını düşünelim bununda sonucu 0 olur ne vakit iki bit te 1 se o zaman sonuç 1 olur tüm bunları lise birinci sınıfı bitirmiş iseniz biliyorsunuzdur.  
Tamam soruya devam edelim harfimiz 1 ile and leniyor bu durumda (isterseniz python üzerinden bunu kolayca test edebilirsiniz) tek sayılarda sonuç 1 çift sayılarda ise sonuç 0 olucak sebebi ise 1 in binary karşılığında ki bitlerden 0 ların arasındaki 1 in konumu bütün tek sayılarda aynı oluyor geri kalan kısım değişiyor, 1 in binary değerinde bir tane 1 var 0 ların arasında bu da bütün tek sayılarda farklılıklar and operatörüyle sıfırlandıktan sonra geriye kalan sonucu 1 e dönüştürüyor deney yaparsanız daha iyi anlayabilirsiniz net ifade edememiş olabilirim. Devam edelim.  
harfimizin ascii tablosunda tekabül ettiği değer tek sayı ise sonuç 1 çıkıcak ve harfimizden 2 çıkarılarak rev_this dosyasına eklenicek eğer çift ise keza bu seferde harfimize 5 eklenicek ve o da dosyaya eklenicek bu dosyadaki son harfe kadar böyle gidicek hatırlarsanız dosyamız 24 karakter uzunluğundaydı bunu flag.txt den okunan değer size ını gördüğümüz için biliyoruz bu for döngüsünün 16h yani 22 karakter sürüceğini de biliyoruz ptr nin harfleri okumaya 0. karakterden başladığını ve 22. de bitiriceğini anlamak zor değil o zaman bir harfimiz kaldı bunun da gene şifrelenmiyen picoctf kalıbının son harfi olan "}" olduğunu tahmin edebiliriz ve evet döngü bittikten sonraki fputc işlemi bu değeri eklemek için var. Yani flag.txt nin ilk 8 karakterine ve son karakterine doknmuyoruz aynen rev_this dosyasına ekliyoruz ve o aradaki kısım ise yukarda detaylandırdığımız algoritma kullanılarak şifreleniyor.  
Bütün bu işlemler daha önce bir sunucuda yapılmış sonuç ise rev_this dosyasında duruyor zaten soruda bizim bunu tersine çevirmemizi istiyor ve şifrelenmiyen bayrağa ulaşmamızı... Geldiğimiz noktada algoritmanın nasıl çalıştığını da bildiğimize göre yapılması gereken bir script yazarak zafere ulaşmak.  
  

```python
sifreli_bayrak = "w1{1wq85jc=2i0<"
bayrak = ""
for i in range(len(sifreli_bayrak)):
    sifre_parcacigi = sifreli_bayrak[i]
    if i&1 != 0:
        sifre_parcacigi = chr(ord(sifre_parcacigi) + 2)
    else:
        sifre_parcacigi = chr(ord(sifre_parcacigi) - 5)
    bayrak += sifre_parcacigi
 
print(bayrak)
```

  
Sonucu picoctf kalıbına sarıyoruz ve evet bayrağamıza ulaştık istersek tek tek python scripti yazmadan da tersine çevirme işlemimizi manuel olarak yapabilirdik ama böylesi daha havalı ve pek tabi uzun bir şifre olma ihtimali de olabilirdi bu yüzden python scripti yazmayı sevin onu kucaklayın bağrınıza basın ondan hoşnutluk duyun.  
Kafanıza takılan bir şey olursa sormaktan çekinmeyin. Selametle.
