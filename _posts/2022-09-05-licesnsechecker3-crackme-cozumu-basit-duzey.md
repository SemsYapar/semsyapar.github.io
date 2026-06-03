---
layout: post
title: "licesnse_checker_3 - crackme çözümü - basit düzey"
date: 2022-09-05
source: "https://www.turkhackteam.org/konular/licesnse_checker_3-crackme-cozumu-basit-duzey.2023440/"
---

Merhaba, bugün c/c++ ile kodlanmış küçük bir crackme, lisans kontrolü yapan bir uygulamayı ele alıcağız. Dilerseniz başlayalım.  
  
**GİRİŞ:**  
Program ı [crackmes.one](https://crackmes.one/) sitesi üzerinden buldum. Site içerisinde zorluk derecelerine göre bissürü crackme bulabilir ve kendi crackme lerinizi paylaşabilirsiniz.  
Crackme linki: [Crackmes](https://crackmes.one/crackme/62327b0433c5d46c8bcc0335)  
  
**ÇÖZÜM:**  
  
Soruyu yapan kişi c/c++ ile yazdığını belirttiği için pasif bilgi toplamak adına DIE kullanmadım. Programı direk IDE ye attım.  
  

![knp513p.png](/pictures/tht/knp513p.png)

  
Main kısmına baktığımda burda programın kendisini argümanla çalıştırıp çalıştırmadığımızı kontrol ettiğini anladım. Buna göre bir hata mesajıda çıkarıyor yani anahtarı programı çalıştırırken vericez. (cmp [rbp+var_24], 2 sayesinde bu kontrol yapılıyor burdaki var_24 offset i kullanilarak hesaplanan adresteki değer argüman sayımızdır, ilk argüman program ın ismidir her zaman, ikincisi, üçüncüsü diye devam eden kısımlar program tarafından kullanılmak üzere değerlendirilir.)  
  

![gvu05xj.png](/pictures/tht/gvu05xj.png)

  
  
Programı bir argümanla çalıştırdığımız takdirde bir döngü içerisine girdiğini görüyoruz. Burda önce bizim girdimizin uzunluğu sıfır olarak başlatılmış bir değişken ([rbp+var_C]) ile karşılaştırılıyor ve eğer sonuç, bizim girdimizin uzunluğundan (strlen fonksyonu ile argumanımızın uzunluğu hesaplanıyor) küçükse döngü devam ediyor, döngüye her girdiğimizde girdimizin sıradaki karakterini alıyoruz ve integer a çevirip var_10 offset i ile belirtilen adrese bu değeri ekliyoruz. Yani argümanımızda ki bütün rakamlari teker teker alıp topluyoruz. Bu görebileceğiniz gibi atoi fonksiyonu ile oluyor standart c fonksiyonlarından biri eğer argümanımızda bir harf var ise bunu 0 olarak yorumluyor yani anahtar olarak sadece sayılar işe yarayacaktır.  
  
For döngüsü ne zaman bizim girdimizin uzunluğu eşit olursa o zaman döngü bitiyor (bu cmp [rbp+var_C], eax bloğu ile kontrol ediliyor dikkatli bakarsanız döngü her bittiğinde var_C nin bir arttırıldığını görüceksiniz. eax register ı da zaten strlen ın dönüş değerini yani argümanımızın uzunluğunu tutuyor olucak). Ardından biriktirdiğimiz sonucun 32h yani 50 ye eşit olup olmadığını kontrol ediyoruz. Bu demektir ki girdiğimiz sayılar ne kadar uzun olursa olsun ki maksimum 50 tane 1 yazabiliriz, toplamı 50 ye eşitse lisansımız doğrulanıyor şimdi bunu test edelim.  
  

![pn6hxh4.png](/pictures/tht/pn6hxh4.png)

  
  
  
Her şey beklediğimiz gibi çalışıyor gördüğünüz gibi daha doğrusu okuduğumuz gibi... Kafanıza takılan bir yer varsa veya eleştirmek istediğiniz bir nokta, saygı çerçevesinde her türlü yoruma açığım. Herkese iyi kraklamalar Selametle kalın.
