---
layout: post
title: "Control Flow Hijacking Analysis and Detection"
categories: blue
---

Selam bugün staj kabulüm için araştırdığım ve kendisi için tespit mekanizmaları geliştirmeye çalışacağım control flow hijacking konusunu irdeleyeceğiz.

## İÇERİKLER
1. - Nedir bu Control Flow Hijacking, diğerlerinden farkı ne ?
2. - Basit Bir Saldırı Örneği
3. - Basit Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları
4. - Karmaşık Bir Saldırı Örneği
5. - Karmaşık Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları
6. - Kapanış


## Nedir bu Control Flow Hijacking, diğerlerinden farkı ne ?

Türkçe "kontrol akışını ele geçirme" şeklinde çevirebiliriz. Anlaşıldığı üzere çook geniş bir saldırı spektrumundan bahsediyoruz bu saldırı türünün içine pwn tarafında bufferoverflow ile stack teki ret adresini ele geçirme yahut heapoverflow ile fonksiyon adreslerinin üzerine shellcode adresimizi yazmak girebilir. Malware tarafında ise dümdüz hedef process in thread lerinden birini durdurup kendi ayarladığımız context i yükleyip shellcode umuzu çalıştırmak gibi fikirler bu saldırı vektörü altında toplanabilir. Kısaca programın olağan akışını durdurmak, zehirlemek yada değiştirmek gibi her türlü faaliyeti Control Flow Hijacking altında değerlendirebiliriz.

## Basit Bir Saldırı Örneği

## Basit Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları

## Karmaşık Bir Saldırı Örneği

## Karmaşık Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları

## Kapanış