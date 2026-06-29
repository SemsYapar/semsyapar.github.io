---
layout: post
title: "Custom VM Çözümü"
categories: blue
date: 2026-06-29
---

# Giriş

[TurkHackTeam](https://www.turkhackteam.org/konular/crack-me-zorluk-9-8-10.2083682) de Egemen tarafından paylaşılan crackme nin analizini içeren bir yazı olacak.

## Açıklama
Ne yazıkki crackme yi çözüp valid key üretemedim. Ama bunun sebebi kanımca crackme nin çözülebilir olarak yapılmamasından kaynaklanıyor.

## protected_crackme.exe ye ilk bakış

Exe nin section larını incelediğimizde soru açıklamasında geçen "lopinki" kelimesinin belliki bir kısaltması olan .lpk adlı özel bir section var. section un ilk byte ları lopinki "LOPNLPK1" adlı bir imza ile başlıyor. AMD64 mimarisi ile derlenmiş.

## protected_crackme entry function analizi

Programın giriş fonksiyonuna baktığımızda bizi bu aralar görmeye çok aşina olduğumuz basic bir api hashing sistemi karşılıyor.

```asm
main:
    mov eax, 1      ; system call number (sys_exit)
    mov ebx, 0      ; exit status 0
    int 0x80        ; call kernel
```