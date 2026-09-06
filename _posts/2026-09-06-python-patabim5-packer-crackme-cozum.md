---
layout: post
title: "Patabim5 ile pack lenen Crackme Çözümü"
date: 2026-09-06
---

# Crackme yi tanıyalım
[THT](https://www.turkhackteam.org/konular/python-ctf-zorluk-3-10-flag.2086306/) de "luvan" adlı üye tarafından paylaşılan bu crackme python ile yazılmış. luvan zorluk seviyesinin 3/10 olduğunu söylemiş. Kullanılan python sürümü 3.14 bilgisi verilmiş. Crackme yi önden çözmek yada incelemek isteyenler için indirme [linki](/sources/Patabim5Crackme/THTCTF.zip). Amacımız "Solved" çıktısına ulaşmak için gereken girdi yi bulmak flag da bu girdi olacak. Haydi başlayalım.

## Genel bakış
Zip i çıkartıp THTCTF klasörüne girdiğimizde bizi birkaç dizin ve dosya karşılıyor.
`
09/06/2026  06:25 PM    <DIR>          .
09/06/2026  06:25 PM    <DIR>          ..
09/06/2026  06:25 PM         2,954,710 D
09/06/2026  06:25 PM               345 main.py
09/06/2026  06:25 PM    <DIR>          ulik1
09/06/2026  06:25 PM    <DIR>          __load
09/06/2026  06:25 PM    <DIR>          __patabim5__
               2 File(s)      2,955,055 bytes
               5 Dir(s)  23,055,990,784 bytes free
`

D adında büyük uzantısız dosya ilgimi çekiyor içine baktığımda okunabilir python kodu görüyorum:  
![D](/pictures/Patabim5Crackme/D.png)  

3 tane daha klasör var bunların hepsinin içinde sadece "__init__.pyc" dosyası var. Python için bu isimlendirmenin özel bir anlamı var. Python da bir kütüphaneyi import ettiğimizde bu kütüphane ismi bir dizinse bu dizindeki __init__ isimli python modülü python kütüphane yükleyicisi tarafından otomatik olarak çalıştırılıyor. Yani ulik1, __load, __patabim5__ isimli dosyaları f