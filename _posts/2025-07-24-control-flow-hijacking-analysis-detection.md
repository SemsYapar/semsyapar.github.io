---
layout: post
title: "Control Flow Hijacking Analysis and Detection"
categories: blue
---

Selam bugün staj kabulüm için araştırdığım ve kendisi için tespit mekanizmaları geliştirmeye çalışacağım control flow hijacking konusunu irdeleyeceğiz.

## İÇERİKLER
1. [Nedir bu Control Flow Hijacking, diğerlerinden farkı ne ?](#nedir-bu-control-flow-hijacking-diğerlerinden-farkı-ne-)
2. [Basit Bir Saldırı Örneği](#basit-bir-saldırı-örneğ)
3. [Basit Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları](#basit-saldırı-örneğine-karşı-statik-ve-dinamik-tespit-mekanizmaları)
4. [Karmaşık Bir Saldırı Örneği](#karmaşık-bir-saldırı-örneği)
5. [Karmaşık Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları](#basit-saldırı-örneğine-karşı-statik-ve-dinamik-tespit-mekanizmaları)
6. [Kapanış](#kapanış)


## Nedir bu Control Flow Hijacking, diğerlerinden farkı ne ?

Türkçe "kontrol akışını ele geçirme" şeklinde çevirebiliriz. Anlaşıldığı üzere çook geniş bir saldırı spektrumundan bahsediyoruz bu saldırı türünün içine pwn tarafında bufferoverflow ile stack teki ret adresini ele geçirme yahut heapoverflow ile fonksiyon pointer larının üzerine shellcode adresimizi yazmak girebilir. Malware tarafında ise dümdüz hedef process in thread lerinden birini durdurup kendi ayarladığımız context i yükleyip shellcode umuzu çalıştırmak gibi fikirler bu saldırı vektörü altında toplanabilir. Kısaca programın olağan akışını durdurmak, zehirlemek yada değiştirmek gibi her türlü faaliyeti Control Flow Hijacking altında değerlendirebiliriz.

## Basit Bir Saldırı Örneği

## Basit Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları

## Karmaşık Bir Saldırı Örneği

## Karmaşık Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları

## Kapanış