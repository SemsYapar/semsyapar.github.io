---
layout: post
title: "Patabim5 ile pack lenen Crackme Çözümü"
date: 2026-09-06
---

# Crackme yi tanıyalım
[THT](https://www.turkhackteam.org/konular/python-ctf-zorluk-3-10-flag.2086306/) de "luvan" adlı üye tarafından paylaşılan bu crackme python ile yazılmış. luvan zorluk seviyesinin 3/10 olduğunu söylemiş. Kullanılan python sürümü 3.14 bilgisi verilmiş. Crackme yi önden çözmek yada incelemek isteyenler için indirme [linki](/sources/Patabim5Crackme/THTCTF.zip). Amacımız "Solved" çıktısına ulaşmak için gereken girdi yi bulmak flag da bu girdi olacak. Konuda bahsedilmeyen ama bence zaman kurtaran bir detay bu crackme linux için arkadaşlar. Kodun kullandığı bazı kütüphanelerin Windows muadili yok olsa bile çok uğraştırıyor o yüzden ben WSL üzerinden çözüme devam ettim. Haydi başlayalım.

## Genel bakış
Zip i çıkartıp THTCTF klasörüne girdiğimizde bizi birkaç dizin ve dosya karşılıyor.  
```
09/06/2026  06:25 PM    <DIR>          .
09/06/2026  06:25 PM    <DIR>          ..
09/06/2026  06:25 PM         2,954,710 D
09/06/2026  06:25 PM               345 main.py
09/06/2026  06:25 PM    <DIR>          ulik1
09/06/2026  06:25 PM    <DIR>          __load
09/06/2026  06:25 PM    <DIR>          __patabim5__
               2 File(s)      2,955,055 bytes
               5 Dir(s)  23,055,990,784 bytes free
```

D adında büyük uzantısız dosya ilgimi çekiyor içine baktığımda okunabilir python kodu görüyorum:  
![D](/pictures/Patabim5Crackme/D.png)  

3 tane daha klasör var bunların hepsinin içinde sadece "\__init__.pyc" dosyası var. Python için bu isimlendirmenin özel bir anlamı var. Python da bir paketi import ettiğimizde bu pakette \__init__ isimli python modülü varsa python paket yükleyicisi bu modülü otomatik olarak çalıştırıyor. Yani ulik1, \__load, \__patabim5__ isimli paketlerdeki init kodlarının çalışması için main.py nin bunları import etmesi yeter.  
main.py içindeki kod şöyle:  
```python
import ulik1
exec(ulik1.ulik2([f'\\x{b:02x}' for b in "\x0a\x56\x55\x48...".encode('latin-1')]))
```
import ulik1, demin söylediğim gibi ulik1 dizinindeki \__init__.pyc kodunun çalıştırılmasını tetikliyor. Sonra ulik1 paketindeki ulik2 isimli bir fonksiyona bir byte dizininin belli bir formata getirilip argüman verildiğini görüyoruz.
Burda şaşırtıcı olan nokta ulik1 altındaki \__init__.pyc yi disassembly edip baktığımızda içinde ulik2 fonksiyonunun tanımlanmamış olduğunu görmemiz. O halde bu fonksiyon nerden geldi? Cevap gene disassembly de.
Öncelikle disassembly ye biraz bakalım. Öbek öbek verilerin decompress edildiğini görüyoruz:
![ulik1_1](/pictures/Patabim5Crackme/ulik1_1.png)
decompress edilen her veri için zlib tekrar tekrar import edilip decompress ve decode fonksiyonları  çağrılıyor. Buralar çok karmaşık o yüzden detaya girmiyeceğim ama tüm bu işlemler sonucu elde edilen veriler marshal.loads ile kod objesi haline getiriliyor sonrada exec ile çalıştırılıyor. exec in kullanıldığını direkt göremiyoruz çünkü o da decompress edilerek elde edilen bir string olarak tutuluyor.

marshal.loads + exec sistemini daha iyi gözlemleyebilmek için iki adet hook ekliyorum main.py ye biri marshal.loads çağrılarını tutacak diğerine exec çağrılarını
```python

orj_exec = builtins.exec

def hook_exec(object, globals=None, locals=None):
    return orj_exec(object, globals, locals)

builtins.exec = hook_exec

orj_loads = marshal.loads

def hook_loads(data):
    return orj_loads(data)

marshal.loads = hook_loads

import ulik1
```
hook ların ikisine de breakpoint koyup kodu çalıştırırsanız ulik1 in import edilmesi anından sonra önce marshal ın sonra exec in çalıştığını görebilirsiniz tabii ilk başta çalışan load ve exec işlemi pyc yi load etmek ve çalıştırmak için yani ilginç değil. Esas ilginç olan çalıştırılan ulik1 in tekrardan loads ı çağırması ve sonra oluşturduğu kod objesini exec etmeye çalışması.


Birkaç standart kütüphane loads ından ve ulik1 in kendi yüklenme sekansından sonra ulike2 nin loads edildiği anı yakalayabildim:  
![ulik2](/pictures/Patabim5Crackme/ulik2_1.png)

artık kod objesi elimde olduğu için hazır debug ediyorken python un dis builtin kütüphanesinin dis fonksiyonu ile kod objesini disassembly edebilirim. Burda dikkat etmeniz gereken tek şey disassembly ettiğiniz python bytecode unun major versiyonunun dis fonksiyonunu çalıştırdığınız python versiyonu ile aynı olması yoksa disassembly işlemi başarısız olur opcode lar python da çok değişken yada xdis gibi genel çözümde kullanabilirsiniz. ulik2 disassembly miz şöyle:  
```
Disassembly of <code object ulik2 at 0x233818f0, file "<ptbm_codecs>", line 2>:
  0           RESUME                   0

  2           LOAD_CONST               0 (<code object ulik2 at 0x233818f0, file "<ptbm_codecs>", line 2>)
              MAKE_FUNCTION
              STORE_NAME               0 (ulik2)
              LOAD_CONST               1 (None)
              RETURN_VALUE

Disassembly of <code object ulik2 at 0x233818f0, file "<ptbm_codecs>", line 2>:
  2           RESUME                   0

  3           BUILD_LIST               0
              STORE_FAST               1 (result)

  4           LOAD_GLOBAL              1 (enumerate + NULL)
              LOAD_FAST_BORROW         0 (byte_list)
              CALL                     1
              GET_ITER
      L1:     FOR_ITER                78 (to L3)
              UNPACK_SEQUENCE          2
              STORE_FAST_STORE_FAST   35 (i, byte)

  5           LOAD_FAST_BORROW         3 (byte)
              LOAD_ATTR                3 (startswith + NULL|self)
              LOAD_CONST               0 ('\\x')
              CALL                     1
              TO_BOOL
              POP_JUMP_IF_TRUE         3 (to L2)
              NOT_TAKEN
              JUMP_BACKWARD           30 (to L1)

  6   L2:     LOAD_GLOBAL              5 (int + NULL)
              LOAD_FAST_BORROW         3 (byte)
              LOAD_CONST               1 (slice(2, None, None))
              BINARY_OP               26 ([])
              LOAD_SMALL_INT          16
              CALL                     2
              STORE_FAST               4 (val)

  7           LOAD_FAST_BORROW_LOAD_FAST_BORROW 66 (val, i)
              BINARY_OP               10 (-)
              STORE_FAST               5 (original_val)

  8           LOAD_FAST_BORROW         1 (result)
              LOAD_ATTR                7 (append + NULL|self)
              LOAD_CONST               0 ('\\x')
              LOAD_FAST_BORROW         5 (original_val)
              LOAD_CONST               2 ('02x')
              FORMAT_WITH_SPEC
              BUILD_STRING             2
              CALL                     1
              POP_TOP
              JUMP_BACKWARD           80 (to L1)

  4   L3:     END_FOR
              POP_ITER

  9           LOAD_CONST               3 ('')
              STORE_FAST               6 (RRRF)

 10           LOAD_FAST_BORROW         1 (result)
              GET_ITER
      L4:     FOR_ITER                11 (to L5)
              STORE_FAST               7 (item)

 11           LOAD_FAST_BORROW_LOAD_FAST_BORROW 103 (RRRF, item)
              BINARY_OP               13 (+=)
              STORE_FAST               6 (RRRF)
              JUMP_BACKWARD           13 (to L4)

 10   L5:     END_FOR
              POP_ITER

 12           LOAD_GLOBAL              9 (exec + NULL)
              LOAD_GLOBAL             10 (bytes)
              LOAD_ATTR               13 (fromhex + NULL|self)
              LOAD_FAST_BORROW         6 (RRRF)
              LOAD_ATTR               15 (replace + NULL|self)
              LOAD_CONST               0 ('\\x')
              LOAD_CONST               3 ('')
              CALL                     2
              CALL                     1
              CALL                     1
              POP_TOP
              LOAD_CONST               4 (None)
              RETURN_VALUE

```

bunu decompile ettiğimizde (claude bu iş için biçilmiş kaftan) şöyle basit bir fonksiyonun tanımlanması işleminden başka bir şey olmadığını görüyoruz:  
```python
def ulik2(byte_list):
    raw_bytes = bytes([int(b[2:], 16) - i for i, b in enumerate(byte_list) if b.startswith(r'\x')])
    exec(raw_bytes)
```
Yani artik ulik2 fonksiyonu var ve ulik1 paketinde tanımlandı. Artık onu çağırabiliriz.  
ulik2 veriyi enumurate ederken şifresini de çözüyor. Çözülen şifreden çıkan veri de legal bir python kod string i olacakki direkt exec ediliyor. Exec edilen şeyin ne olduğuna artık bakabiliriz ne de olsa kendi ulik2 imiz var. exec yerine print ettirelim:  
```python
def ulik2(byte_list):
    raw_bytes = bytes([int(b[2:], 16) - i for i, b in enumerate(byte_list) if b.startswith(r'\x')])
    print(raw_bytes)

#import ulik1
arg1 = [f'\\x{b:02x}' for b in "\x0a\x56\x55\x48\x41...".encode('latin-1')]
ulik2(arg1)
```
Çıktı: `b'\nUSE= open("D","r").read()\nimport __load\nexec(__load.UL20503(USE))\n'`  
Düzenleyelim:  
```python
USE= open("D","r").read()
import __load
exec(__load.UL20503(USE))
```
Şimdiden sinir bozucu hale gelmeye başladı:D Ama artık ulik1 i import etmemize gerek yok. Çünkü onun işinin ne olduğunu biliyoruz bu kodu çalıştırmak. Bu koddan devam edelim. \__load paketinin import edildiğini görüyoruz. Bu sefer diğerinde yaptığım gibi onun disassembly sini göstermiyeceğim çok benzer çünkü. Ard arda bissürü decompress ve decode. Sonra marshal.loads ile bu parçalardan `<ptbm_codecs>` dosya ismine sahip kod objesi oluşturucaz. oluşturduğumuz bu kod objesini exec edicez. Bu sefer exec edilen kod sadece fonksiyon tanımlamıyor kendi kendine bir işlem de yapıyor:  
```
  0           RESUME                   0

  2           LOAD_SMALL_INT           0
              LOAD_CONST               1 (None)
              IMPORT_NAME              0 (marshal)
              STORE_NAME               0 (marshal)
              LOAD_SMALL_INT           0
              LOAD_CONST               1 (None)
              IMPORT_NAME              1 (base64)
              STORE_NAME               1 (base64)
              LOAD_NAME                1 (base64)
              LOAD_ATTR                4 (b64decode)
              PUSH_NULL
              LOAD_CONST               2 ('4wAAAAAAAAAAAAAAAAQAAAAAAAAA83wAAACAAF4AUgFJAEgBdAJ...')
              CALL                     1
              STORE_NAME               3 (_ULLLL)
              LOAD_NAME                4 (exec)
              PUSH_NULL
              LOAD_NAME                0 (marshal)
              LOAD_ATTR               10 (loads)
              PUSH_NULL
              LOAD_NAME                3 (_ULLLL)
              CALL                     1
              CALL                     1
              POP_TOP
              LOAD_CONST               1 (None)
              RETURN_VALUE
```
base64 decode + marshal loads + exec. Exec edilen şeyin ne olduğunu anlamak için exec hook uma yakalanmasını bekliyorum. Yada marshal hook umu beklerim. Fark etmez sonuç olarak kod objesini elde edip disassembly edicem:  
```
  0           RESUME                   0

  1           LOAD_SMALL_INT           0
              LOAD_CONST               1 (('Cipher', 'algorithms', 'modes'))
              IMPORT_NAME              0 (cryptography.hazmat.primitives.ciphers)
              IMPORT_FROM              1 (Cipher)
              STORE_NAME               2 (CCC)
              IMPORT_FROM              3 (algorithms)
              STORE_NAME               4 (__46346)
              IMPORT_FROM              5 (modes)
              STORE_NAME               6 (_36x)
              POP_TOP

  2           LOAD_SMALL_INT           0
              LOAD_CONST               2 (('default_backend',))
              IMPORT_NAME              7 (cryptography.hazmat.backends)
              IMPORT_FROM              8 (default_backend)
              STORE_NAME               9 (___7)
              POP_TOP

  3           LOAD_SMALL_INT           0
              LOAD_CONST               3 (None)
              IMPORT_NAME             10 (base64)
              STORE_NAME              11 (A)

  4           LOAD_CONST               4 (<code object ______________________________________ at 0x1a1160b0, file "<string>", line 4>)
              MAKE_FUNCTION
              STORE_NAME              12 (______________________________________)

 13           LOAD_NAME               13 (bytes)
              LOAD_ATTR               29 (fromhex + NULL|self)
              LOAD_CONST               5 ('cbdadcca476247efd9e696823ee5a84436c9b111aa73cca5edc3fa7cb7c3d526')
              CALL                     1
              STORE_NAME              15 (_______483275622356723756239)

 14           LOAD_CONST               6 (b'6+R9Ub/scZRkdYbLcbSd/6YU+Ao8JJXzeMzHqH8ijTfI...')
              STORE_NAME              16 (ISBAYT)

 15           LOAD_NAME               12 (______________________________________)
              PUSH_NULL
              LOAD_NAME               16 (ISBAYT)
              LOAD_NAME               15 (_______483275622356723756239)
              CALL                     2
              STORE_NAME              17 (r)

 16           LOAD_NAME               18 (exec)
              PUSH_NULL
              LOAD_NAME               17 (r)
              CALL                     1
              POP_TOP
              LOAD_CONST               3 (None)
              RETURN_VALUE

Disassembly of <code object ______________________________________ at 0x1a1160b0, file "<string>", line 4>:
  4           RESUME                   0

  5           LOAD_GLOBAL              0 (A)
              LOAD_ATTR                2 (b64decode)
              PUSH_NULL
              LOAD_FAST_BORROW         0 (_11)
              CALL                     1
              STORE_FAST               2 (___ULLl456476)

  6           LOAD_FAST_BORROW         2 (___ULLl456476)
              LOAD_CONST               0 (slice(None, 12, None))
              BINARY_OP               26 ([])
              STORE_FAST               3 (_326756485)

  7           LOAD_FAST_BORROW         2 (___ULLl456476)
              LOAD_CONST               1 (slice(12, 28, None))
              BINARY_OP               26 ([])
              STORE_FAST               4 (_______483275672356723756239)

  8           LOAD_FAST_BORROW         2 (___ULLl456476)
              LOAD_CONST               2 (slice(28, None, None))
              BINARY_OP               26 ([])
              STORE_FAST               5 (__________fg7834rtfg834t8375t8t)

  9           LOAD_GLOBAL              5 (CCC + NULL)
              LOAD_GLOBAL              6 (__46346)
              LOAD_ATTR                8 (AES)
              PUSH_NULL
              LOAD_FAST_BORROW         1 (__23)
              CALL                     1
              LOAD_GLOBAL             10 (_36x)
              LOAD_ATTR               12 (GCM)
              PUSH_NULL
              LOAD_FAST_BORROW_LOAD_FAST_BORROW 52 (_326756485, _______483275672356723756239)
              CALL                     2
              LOAD_GLOBAL             15 (___7 + NULL)
              CALL                     0
              LOAD_CONST               3 (('backend',))
              CALL_KW                  3
              STORE_FAST               6 (______________)

 10           LOAD_FAST_BORROW         6 (______________)
              LOAD_ATTR               17 (decryptor + NULL|self)
              CALL                     0
              STORE_FAST               7 (_x)

 11           LOAD_FAST_BORROW         7 (_x)
              LOAD_ATTR               19 (update + NULL|self)
              LOAD_FAST_BORROW         5 (__________fg7834rtfg834t8375t8t)
              CALL                     1
              LOAD_FAST_BORROW         7 (_x)
              LOAD_ATTR               21 (finalize + NULL|self)
              CALL                     0
              BINARY_OP                0 (+)
              STORE_FAST               8 (EZE4576)

 12           LOAD_FAST_BORROW         8 (EZE4576)
              LOAD_ATTR               23 (decode + NULL|self)
              CALL                     0
              RETURN_VALUE
```
base64 decode + AES decrpytion + exec görüyoruz. Programı tekrar devam edip exec hook umu bekliyorum, hemen düşmüyor çünkü crpyto kütüphanesinin birkaç init işlemi görülüyor ama birkaç kez devam ettirince sonunda istediğim exec i buluyorum:  


UL20503 fonksiyonunu çalıştırıcaz ve bu fonksiyonun içine D dosyasındaki koca veriyi argüman olarak vericez. Sonucu da tekrar exec edicez. Recursive exec ler bu işin temeli:D
D verisinin içinde çok sayıda constant anlamsız gözüken parça var. UL20503 bu parçaları esas kod byte ları ile değiştirip D verisinin gerçek bir kod objesine dönüştürülebilmesini sağlıyor. İşte UL20503 den küçük bir kesit:  
![UL20503](/pictures/Patabim5Crackme/UL20503.png)

UL20503 bu işlemi bitirdikten sonra düzeltilmiş D kod objesini çalıştırıyor:  
![UL20503_2](/pictures/Patabim5Crackme/UL20503_2.png)
çalıştırılan düzeltilmiş D kod objesini gözlemleyebilmek için bu seferde exec builtin fonksiyonunu hook layalım:  
