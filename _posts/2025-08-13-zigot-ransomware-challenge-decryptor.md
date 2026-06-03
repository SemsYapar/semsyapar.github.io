---
layout: post
title: "Zigot Ransomware Challenge"
categories: blue
date: 2025-08-13
---


[Malwation](https://www.malwation.com/) ekibinin hazırladığı [CTF](https://vx.zone/) yarışmasının ZIGOTRANSOMWARE CHALLENGE adlı sorusunun çözümü:

bu şekilde bir dosya atalım içeri ve program çalıştıralım
![zig1](/pictures/zig1.png)

program çalışır çalışmaz 3 adet dosya üretiyor hedef Desktop/test klasöründe
![zig2](/pictures/zig2.png)

dizinde bulduğu tüm dosyaları şifreliyor hatta kendi readme sini bile şifreliyor

programın çalıştırdığı bazı dikkat çekici fonksiyonlara baktığımızda neredeyse sanallaştırılma işlemi uygulanmış diyebileceğim kadar karmaşık switch case ler göze çarpıyor
![zig3](/pictures/zig3.png)
bunlardan 2-3 tane var ve iç içe veya ard arda çalışıyorlar bu noktada bazı önemli olabilecek api lere breakpoint koymanın sürecimi hızlandıracağını düşündüm

importtable a baktığımda ntcreatefile ın kullanıldığını gördüm bir ransomware için fena bir seçim değil kullanıldığı yerlere breakpoint koyup incelediğimde bir parça gözüme çarptı

![zig4](/pictures/zig4.png)
yaptığım isimlendirmelerden anlaşıldığı üzere hedef klasördeki okunan dosyalara muamele edilen kısımın belli bir parçasını görüyorsunuz

burda copytov51 şeklinde isimlendirdiğim fonksiyon dword_7FF752BC0A0C adresindeki 16byte lık aes key ini extanded key e dönüştürüp 51v adresine koyuyor sonra bu extanded key sayesinde aes algoritması input u şifreliyor
Aes algoritması simetrik çalıştığı için şifrelenmiş verili dosyanın .encrypted uzantısını silip programı tekrar çalıştırırsanız program tekrar şifreleyim derken aslında şifreyi çözüyor(.encrypted uzantısı olmayan dosyaların şifreleneceği şekilde bir algoritma işlenmiş programda)
geri kalan kısım ise açıklanmaya gerek duyulmayacak kadar anlaşılır. Şifrelenen input tekrardan hedef file a yazılıyor



decryptor u yazmak için bana bu kadar bilgi yetti aslında daha fazlası da var mesela. Kağan bey in walpaper ımı elaleme reklam yapmasını sağlayan bir server iletişim kısmıda var ransomware de ss alınıyor ve bazı bilgiler toplanıyor falan filan.


decryptor umuzda bu şekilde:
```python
import os
from pathlib import Path
from Crypto.Cipher import AES

"""
malware desktop/test altındaki dosyaları şifreleyip .encrypted uzantılı hale getiriyor.
bunu yaparken aes128 ctr modunu kullanıyor.
bu işlemi sub_7FF752ADAFE6 fonksiyonunda yapıyor.
expaneded key in boyutu 176 byte olduğunu tespit edince aklima direkt aes128 ctr geldi desem yalan olur chatgpt böyle söyledi.
python un crypto kütüphanesi ilk 16 byte verdiliği takdirde expanded key i otomatik olarak oluşturuyor.
bu yüzden 16 byte ını hardcoded olarak tutulduğu adresten(dword_7FF752BC0A0C) aldım copytov51 fonksiyonundan görebilirsiniz
daha detaylı bir şey yazıcam ama zaman önceliği dolayısıyla şimdilik bu kadar açıklama yazdım
"""



# AES key ve nonce
key_bytes = bytes([
    0xB4, 0x0A, 0xA0, 0x77, 0xE5, 0x21, 0x5C, 0xCF,
    0x65, 0x38, 0xC5, 0x06, 0xA6, 0x51, 0xA3, 0x35
])
nonce = b'\x00' * 8

# Desktop/test klasörü
desktop_path = Path(os.environ['USERPROFILE']) / 'Desktop' / 'test'

if not desktop_path.exists():
    print(f"Klasör bulunamadı: {desktop_path}")
else:
    encrypted_files = [f for f in desktop_path.iterdir() if f.is_file() and f.suffix == '.encrypted']

    if not encrypted_files:
        print("Hiç .encrypted dosyası bulunamadı.")
    else:
        print("İşleniyor...")

        for f in encrypted_files:
            with open(f, 'rb') as infile:
                ciphertext = infile.read()

            # AES CTR decrypt
            cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)

            # .cleaned olarak kaydet
            cleaned_file = f.with_suffix('.cleaned')
            with open(cleaned_file, 'wb') as outfile:
                outfile.write(plaintext)

            print(f"{f.name} → {cleaned_file.name} olarak çözüldü.")

```

POC:
<video width="640" height="360" controls>
  <source src="/videos/zig1.mkv" type="video/mp4">
  Tarayıcınız video etiketini desteklemiyor.
</video>