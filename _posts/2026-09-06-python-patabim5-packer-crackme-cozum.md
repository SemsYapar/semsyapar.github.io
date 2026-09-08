---
layout: post
title: "Patabim5 ile pack lenen Crackme Çözümü ve Analizi"
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
import ulik1, demin söylediğim gibi ulik1 dizinindeki \__init__.pyc kodunun çalıştırılmasını tetikliyor. Sonra ulik1 paketindeki ulik2 isimli bir fonksiyona bir byte dizininin belli bir formata getirilip argüman olarak verildiğini görüyoruz.
Burda şaşırtıcı olan nokta ulik1 altındaki \__init__.pyc yi disassembly edip baktığımızda içinde ulik2 fonksiyonunun tanımlanmamış olduğunu görmemiz. O halde bu fonksiyon nerden geldi? Cevap gene disassembly de.
Öncelikle disassembly ye biraz bakalım. Öbek öbek verilerin decompress edildiğini görüyoruz:
![ulik1_1](/pictures/Patabim5Crackme/ulik1_1.png)  
decompress edilen her veri için zlib tekrar tekrar import edilip decompress ve decode fonksiyonları  çağrılıyor. Buralar çok karmaşık o yüzden detaya girmiyeceğim ama tüm bu işlemler sonucu elde edilen veriler marshal.loads ile kod objesi haline getiriliyor sonrada exec ile çalıştırılıyor. exec in kullanıldığını direkt göremiyoruz çünkü o da decompress edilerek elde edilen bir string olarak tutuluyor.

marshal.loads + exec sistemini daha iyi gözlemleyebilmek için iki adet hook ekliyorum main.py ye biri marshal.loads çağrılarını tutacak diğerine exec çağrılarını
```python
orj_exec = builtins.exec

def hook_exec(code, *args):
    return orj_exec(code, *args)

builtins.exec = hook_exec

orj_loads = marshal.loads

def hook_loads(data):
    return orj_loads(data)

marshal.loads = hook_loads

import ulik1
```
hook ların ikisine de breakpoint koyup kodu çalıştırırsanız ulik1 in import edilmesi anından sonra önce marshal.loads ın sonra exec in çalıştığını görebilirsiniz tabii ilk başta çalışan load ve exec işlemi pyc yi load etmek ve çalıştırmak için python yükleyicisi tarafından tetiklenecek birkaç tane standart kütüphane load ı da olabilir bunları geçmeniz lazım. Bir süre sonra co_filename inin `<ptbm_codecs>` olduğu bir modülün yüklendiğini göreceksiniz modülün names kısmına bakarsanız ulik2 nin bu modülde tanımlanan bir fonksiyon olduğunu görebilirsiniz. Bu modülü disassembly edip incelediğinizde ulik2 fonksiyonunun tanımlanmasını sağlayan bir koddan ibaret olduğunu görebilirsiniz.

ulike2 nin loads edildiği an:  
![ulik2](/pictures/Patabim5Crackme/ulik2_1.png)  

ulik2 disassembly si: 
```
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

bunu decompile ettiğimizde (claude bu iş için biçilmiş kaftan)
```python
def ulik2(byte_list):
    raw_bytes = bytes([int(b[2:], 16) - i for i, b in enumerate(byte_list) if b.startswith(r'\x')])
    exec(raw_bytes)
```
Yani artik ulik2 fonksiyonu var ve ulik1 paketinde tanımlandı. Ne olduğunu bildiğimiz için istersek onu kendimizde çağırabiliriz.  
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
Şimdiden sinir bozucu hale gelmeye başladı:D Ama artık ulik1 i import etmemize gerek yok. Çünkü onun işinin ne olduğunu biliyoruz bu kodu çalıştırmak. Bu koddan devam edelim. \__load paketinin import edildiğini görüyoruz. marshal.loads ve exec hook larımız hala yerinde. Go latalım:  
```python
orj_exec = builtins.exec

def hook_exec(code, *args):
    return orj_exec(code, *args)

builtins.exec = hook_exec

orj_loads = marshal.loads

def hook_loads(data):
    return orj_loads(data)

marshal.loads = hook_loads

import __load
```
Birkaç exec e aynı şekilde izin verdikten sonra gene o pattern i görüyoruz `<ptbm_codecs>` isimli modül yükleniyor ve exec ile çalıştırılıyor. Bu sefer işi fonksiyon tanımlamak değil. Daha aktif bir işi var. Disassembly ye bakalım:
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
base64 decode + marshal.loads + exec. Exec edilen şeyin ne olduğunu anlamak için gene exec hook uma yakalanmasını bekliyorum. Yada marshal hook umu beklerim. Fark etmez sonuç olarak kod objesini elde edip disassembly edicem:  
```
  0          0       RESUME                   0

  1          2       LOAD_SMALL_INT           0
             4       LOAD_CONST               1 (('Cipher', 'algorithms', 'modes'))
             6       IMPORT_NAME              0 (cryptography.hazmat.primitives.ciphers)
             8       IMPORT_FROM              1 (Cipher)
            10       STORE_NAME               2 (CCC)
            12       IMPORT_FROM              3 (algorithms)
            14       STORE_NAME               4 (__46346)
            16       IMPORT_FROM              5 (modes)
            18       STORE_NAME               6 (_36x)
            20       POP_TOP

  2         22       LOAD_SMALL_INT           0
            24       LOAD_CONST               2 (('default_backend',))
            26       IMPORT_NAME              7 (cryptography.hazmat.backends)
            28       IMPORT_FROM              8 (default_backend)
            30       STORE_NAME               9 (___7)
            32       POP_TOP

  3         34       LOAD_SMALL_INT           0
            36       LOAD_CONST               3 (None)
            38       IMPORT_NAME             10 (base64)
            40       STORE_NAME              11 (A)

  4         42       LOAD_CONST               4 (<code object ______________________________________ at 0xb8f0b10, file "<string>", line 4>)
            44       MAKE_FUNCTION
            46       STORE_NAME              12 (______________________________________)

 13         48       LOAD_NAME               13 (bytes)
            50       LOAD_ATTR               29 (fromhex + NULL|self)
            70       LOAD_CONST               5 ('cbdadcca476247efd9e696823ee5a84436c9b111aa73cca5edc3fa7cb7c3d526')
            72       CALL                     1
            80       STORE_NAME              15 (_______483275622356723756239)

 14         82       LOAD_CONST               6 (b'6+R9Ub/scZRkdYbLcbSd/6YU+Ao8JJXzeMzHqH8ijTfIoysV5dq0ChFUA...')
            84       STORE_NAME              16 (ISBAYT)

 15         86       LOAD_NAME               12 (______________________________________)
            88       PUSH_NULL
            90       LOAD_NAME               16 (ISBAYT)
            92       LOAD_NAME               15 (_______483275622356723756239)
            94       CALL                     2
           102       STORE_NAME              17 (r)

 16        104       LOAD_NAME               18 (exec)
           106       PUSH_NULL
           108       LOAD_NAME               17 (r)
           110       CALL                     1
           118       POP_TOP
           120       LOAD_CONST               3 (None)
           122       RETURN_VALUE

Disassembly of <code object ______________________________________ at 0xb8f0b10, file "<string>", line 4>:
  4          0       RESUME                   0

  5          2       LOAD_GLOBAL              0 (A)
            12       LOAD_ATTR                2 (b64decode)
            32       PUSH_NULL
            34       LOAD_FAST_BORROW         0 (_11)
            36       CALL                     1
            44       STORE_FAST               2 (___ULLl456476)

  6         46       LOAD_FAST_BORROW         2 (___ULLl456476)
            48       LOAD_CONST               0 (slice(None, 12, None))
            50       BINARY_OP               26 ([])
            62       STORE_FAST               3 (_326756485)

  7         64       LOAD_FAST_BORROW         2 (___ULLl456476)
            66       LOAD_CONST               1 (slice(12, 28, None))
            68       BINARY_OP               26 ([])
            80       STORE_FAST               4 (_______483275672356723756239)

  8         82       LOAD_FAST_BORROW         2 (___ULLl456476)
            84       LOAD_CONST               2 (slice(28, None, None))
            86       BINARY_OP               26 ([])
            98       STORE_FAST               5 (__________fg7834rtfg834t8375t8t)

  9        100       LOAD_GLOBAL              5 (CCC + NULL)
           110       LOAD_GLOBAL              6 (__46346)
           120       LOAD_ATTR                8 (AES)
           140       PUSH_NULL
           142       LOAD_FAST_BORROW         1 (__23)
           144       CALL                     1
           152       LOAD_GLOBAL             10 (_36x)
           162       LOAD_ATTR               12 (GCM)
           182       PUSH_NULL
           184       LOAD_FAST_BORROW_LOAD_FAST_BORROW 52 (_326756485, _______483275672356723756239)
           186       CALL                     2
           194       LOAD_GLOBAL             15 (___7 + NULL)
           204       CALL                     0
           212       LOAD_CONST               3 (('backend',))
           214       CALL_KW                  3
           222       STORE_FAST               6 (______________)

 10        224       LOAD_FAST_BORROW         6 (______________)
           226       LOAD_ATTR               17 (decryptor + NULL|self)
           246       CALL                     0
           254       STORE_FAST               7 (_x)

 11        256       LOAD_FAST_BORROW         7 (_x)
           258       LOAD_ATTR               19 (update + NULL|self)
           278       LOAD_FAST_BORROW         5 (__________fg7834rtfg834t8375t8t)
           280       CALL                     1
           288       LOAD_FAST_BORROW         7 (_x)
           290       LOAD_ATTR               21 (finalize + NULL|self)
           310       CALL                     0
           318       BINARY_OP                0 (+)
           330       STORE_FAST               8 (EZE4576)

 12        332       LOAD_FAST_BORROW         8 (EZE4576)
           334       LOAD_ATTR               23 (decode + NULL|self)
           354       CALL                     0
           362       RETURN_VALUE

```
base64 decode + AES decrpytion + exec görüyoruz. Programı tekrar devam edip bu modüldeki exec hook umu bekliyorum gene hemen düşmüyor çünkü crpyto kütüphanesinin birkaç init işlemi görülüyor ama birkaç kez devam ettirince sonunda istediğim exec i buluyorum, yani aslında bulamıyorum çünkü hook um yüzünden `<string>` modülünün diğerleri gibi veriyi decrypt edip çağırdığı exec işlemine gelemeden modülün ortasında bir hata alıyorum:  
`name 'A' is not defined`
A ne? Evet disassembly yi okuduysanız bunu biliyorsunuz offset 40 a bakarsanız base64 modülünün isminin 'A' isimli bir değişkene kaydedildiğini görüyoruz. Bu neden bizim exec hook umuzu bozuyor? Anlamak için traceback analizi yapabiliriz:  
```python
orijinal_exec = builtins.exec

def hook_exec(code, *args):
    try:
        orijinal_exec(code, *args)
    except Exception as e:
        saved_tb = e.__traceback__

builtins.exec = hook_exec
```
Hook umu bu hale getiriyorum ve exception a düşmesini bekliyorum. Beklediğim gibi de oluyor. \__traceback__ nesnesinde exception zincirini bulabiliyoruz. Zincirde en geriye gittiğimizde ve 'lasti' alanına baktığımızda hangi offset de exception un oluştuğunu görebiliyoruz buda `______________________________________` fonksiyonunun 2. offset i imiş. Hemen bakalım ne var orda:  
"2       LOAD_GLOBAL              0 (A)"
A global değişken olarak yüklenmeye çalışıyor. Artık neden hatanın oluştuğunu biliyoruz. Biz exec i hook ladığımızda onu hook fonksiyonumuzun local scope unda çalıştırmış oluyoruz bu yüzden 40. offset deki A değişken tanımı normalde direkt modül üzerinde tanımlanan global bir değişken olacakken sadece bizim fonksiyonumuzda tanımlanmış oluyor sonrada LOAD_GLOBAL global değişkenler arasında A yı bulamayınca hata veriyor. Bu problemi çözmek için A değişkeninin default hook fonksiyonumuzda tanımlanmamasını sağlamak adına kendimiz bir scope yaratıp exec in onu kullanmasını sağlayacağız. böylece A orda tanımlanacak sonrasında A yi arayan fonksiyonda bu scope da arayacak ve bulacak.

```python
orijinal_exec = builtins.exec
scope = {}
def hook_exec(code, *args):
    if len(args) == 0:
        return orijinal_exec(code, scope)
    orijinal_exec(code, *args)

builtins.exec = hook_exec
```
if i koymamın sebebi eğer exec i çağıran diğer işlemler mesela crpyto kütüphanesi kendi global değerini kullanmak isterse onu scope umla ezmiyim kendininkini kullanmasına izin vereyim ki sorun çıkmasın. Yapmazsak çıkıyor.  
Böylece A tanımlanma hatasını çözmüş oluyoruz ki sadece A değil CCC diye bir değişken de başka bir kütüphane için kullanılıyor onuda çözmüş oluyoruz. Bence bu kasıtlı idi yani A ve CCC değişkenlerinin varlığı büyük ihtimal packer i yapan exec fonksiyonunun hook lanmasını zorlaştırmak için sabit kütüphaneleri özel değişkenlere kaydedip kullanma yolunu seçti ilerde exec fonksiyonunun hook lanmasını başka türlü kontrol ettiğini de göreceğiz.  
Hedef exec imize ulaşıyoruz hook fonksiyonumuzla. exec e gelen argüman ise şöyle:  
```python
print=None\nexec(__import__("base64").b64decode(b"CmV4ZW"+b"MoX19pbXBvcnRfXygiYmFzZTY0IikuYjY0..."))\n
```
Bunun çalışmasına izin vericem sonuçta yaptığı decode edip tekrar exec yapmak bir kere daha hook umuza exec in gelmesini bekleyelim:  
```
\nexec(__import__("base64").b64decode(b"I2xpYi9fX2luaXRfXy5weQpjbGFzcyBfSGZmMzQ2Mjg..."))\ndef UL20503(_88):\n    XX = [\n        _UL67348._(1),\n        _UL67348._(4),\n        _UL67348._(int(__import__(\'math\').sqrt((lambda x: (x**5 - 10*x**4 + 35*x**3 - 50*x**2 + 24*x + 16))(2)))**2 // 4),\n        "_",\n        _UL67348._(18-8+5+3+2-2-2+2),\n        _UL67348._(3),\n        _UL67348._(int((lambda x: (x**4 - 4*x**3 + 6*x**2 + 4*x + 8))(2))) ,\n        "_",\n        _UL67348._(18+1000+1000+103-2103),\n        _UL67348._(4),\n        \n    ]\n    _UL35FAHRER = _UL67348._uAR(_UL67348.AT(_UL67348.R(str(XX[0]+XX[1]+XX[2]+XX[3]+XX[4]+XX[5]+XX[6]+XX[7]+XX[8]+XX[9]+XX[6]))))\n    _UL45729 = _UL67348._uAR(_UL67348._uAR(_UL67348._uAR(_UL67348._uAR(__import__("base64").b64decode(\'RkZGMzg1NDYzNzYyNTY4\')))))\n    _XFFF = _UL67348._uI364633(_UL45729.decode())\n    Ul20250 =_88\\\n    .replace(_XFFF, r"\\x00")\\\n    .replace(_UL67348.AT(_UL67348._uAR(_UL67348.R(_UL67348.FF(b"852425f5851425f565f4d4").decode()))), r"\\x01")\\\n    .replace(_UL35FAHRER.upper(), r"\\x02")\\\n    .replace(_UL67348._uAR(_UL67348._uAR("SUB_R8_R9")), r"\\x03")\\\n    .replace("JMP_SHORT", r"\\x04")\\\n    .replace("CALL_CDEF_SECURE", r"\\x05")\\\n    .replace("RET_FAR", r"\\x06")\\\n    .replace("PUSH_RBP", r"\\x07")\\\n    .replace("POP_RDI", r"\\x08")\\\n    .replace("XOR_RAX_RCX", r"\\x09")\\\n    .replace(_UL67348._uAR(_UL67348._uAR(_UL67348._uAR(_Hff346283._Hff346283__AXX("Vm1wR2EwMUhSWGhUV0d4VVlteEtXRll3WkZOWlZsSlZVMnBTVlZKdGVGbGFWVll3WVd4S2RWRnJiRnBOUmxWNFZrZDRTbVZIVGtkVWJGcFRZa1ZaZWxaVldrWlBWa0pTVUZRd1BRPT0="+_Hff346283._f("FFR")))))+"ND_RDX_RSI", r"\\x0a")\\\n    .replace("OR_R8_R10", r"\\x0b")\\\n    .replace("NOT_R11", r"\\x0c")\\\n    .replace("SHL_RAX_4", r"\\x0d")\\\n    .replace("SHR_RBX_2", r"\\x0e")\\\n    .replace("CMP_RCX_RDX", r"\\x0f")\\\n    .replace("JE_ZERO_FLAG", r"\\x10")\\\n    .replace("JNE_NOT_ZERO", r"\\x11")\\\n    .replace("JG_GREATER", r"\\x12")\\\n    .replace("JL_LESS", r"\\x13")\\\n    .replace("JGE_GREATER_EQ", r"\\x14")\\\n    .replace("JLE_LESS_EQ", r"\\x15")\\\n    .replace("INC_RAX", r"\\x16")\\\n    .replace("DEC_RBX", r"\\x17")\\\n    .replace("MUL_RAX_RBX", r"\\x18")\\\n    .replace("DIV_RCX_8", r"\\x19")\\\n    .replace("MOD_RDX_RAX", r"\\x1a")\\\n    .replace("MOVB_AL_BL", r"\\x1b")\\\n    .replace("MOVW_AX_BX", r"\\x1c")\\\n    .replace("MOVL_EAX_EBX", r"\\x1d")\\\n    .replace("LEA_RAX_RBP", r"\\x1e")\\\n    .replace("NOP_SLEEP", r"\\x1f")\\\n    .replace("HLT_STOP", r"\\x20")\\\n    .replace("INT_80_SYSCALL", r"\\x21")\\\n    .replace("IRET_RETURN", r"\\x22")\\\n    .replace("CLI_DISABLE", r"\\x23")\\\n    .replace("STI_ENABLE", r"\\x24")\\\n    .replace("CLC_CLEAR", r"\\x25")\\\n    .replace("STC_SET", r"\\x26")\\\n    .replace("CMC_COMPLEMENT", r"\\x27")\\\n    .replace("PUSHF_FLAGS", r"\\x28")\\\n    .replace("POPF_FLAGS", r"\\x29")\\\n    .replace("TEST_RAX_RAX", r"\\x2a")\\\n    .replace("BSWAP_EAX", r"\\x2b")\\\n    .replace("XCHG_RAX_RBX", r"\\x2c")\\\n    .replace("XLAT_TABLE", r"\\x2d")\\\n    .replace("DAA_DECIMAL", r"\\x2e")\\\n    .replace("DAS_DECIMAL", r"\\x2f")\\\n    .replace(_UL67348._uAR(_UL67348._uAR(_UL67348._uAR(_Hff346283._Hff346283__AXX("ZmQrdQ=="))))+\n    _UL67348._uAR(_UL67348._uAR(_UL67348._uAR(_Hff346283._Hff346283__AXX("fg78234tfbdu23bd2837rgf"))))+\n    _UL67348._uAR(_UL67348._uAR(_UL67348._uAR(_Hff346283._Hff346283__AXX("1ydf2gy8dg28"))))\n    +"_ASCII", r"\\x30")\\\n    .replace("AAS_ASCII", r"\\x31")\\\n    .replace("AAM_ASCII", r"\\x32")\\\n    .replace("AAD_ASCII", r"\\x33")\\\n    .replace("CBW_CONVERT", r"\\x34")\\\n    .replace("CWD_CONVERT", r"\\x35")\\\n    .replace("CWDE_CONVERT", r"\\x36")\\\n    .replace("CDQ_CONVERT", r"\\x37")\\\n    .replace("PUSHA_ALL", r"\\x38")\\\n    .replace("POPA_ALL", r"\\x39")\\\n    .replace("BOUND_CHECK", r"\\x3a")\\\n    .replace("ENTER_STACK", r"\\x3b")\\\n    .replace("LEAVE_STACK", r"\\x3c")\\\n    .replace("UD2_UNDEFINED", r"\\x3d")\\\n    .replace("SYSCALL_CDEF", r"\\x3e")\\\n    .replace("SYSRET_CDEF", r"\\x3f")\\\n    .replace("SYSENTER_CDEF", r"\\x40")\\\n    .replace("SYSEXIT_CDEF", r"\\x41")\\\n    .replace("RDMSR_READ", r"\\x42")\\\n    .replace("WRMSR_WRITE", r"\\x43")\\\n    .replace("RDTSC_TIME", r"\\x44")\\\n    .replace("CPUID_INFO", r"\\x45")\\\n    .replace("IN_PORT", r"\\x46")\\\n    .replace("OUT_PORT", r"\\x47")\\\n    .replace("HALT_SYSTEM", r"\\x48")\\\n    .replace("LOCK_PREFIX", r"\\x49")\\\n    .replace("REP_PREFIX", r"\\x4a")\\\n    .replace("REPE_PREFIX", r"\\x4b")\\\n    .replace("REPNE_PREFIX", r"\\x4c")\\\n    .replace("JMP_FAR_CDEF", r"\\x4d")\\\n    .replace("CALL_FAR_CDEF", r"\\x4e")\\\n    .replace("RET_FAR_CDEF", r"\\x4f")\\\n    .replace("IRETD_CDEF", r"\\x50")\\\n    .replace("ROL_ROTATE", r"\\x51")\\\n    .replace("ROR_ROTATE", r"\\x52")\\\n    .replace("RCL_ROTATE", r"\\x53")\\\n    .replace("RCR_ROTATE", r"\\x54")\\\n    .replace("SAL_SHIFT", r"\\x55")\\\n    .replace("SAR_SHIFT", r"\\x56")\\\n    .replace("IMUL_SIGNED", r"\\x57")\\\n    .replace("IDIV_SIGNED", r"\\x58")\\\n    .replace("NEG_COMPLEMENT", r"\\x59")\\\n    .replace("NOT_COMPLEMENT", r"\\x5a")\\\n    .replace("SETO_OVERFLOW", r"\\x5b")\\\n    .replace("SETNO_NO_OVERFLOW", r"\\x5c")\\\n    .replace("SETB_BELOW", r"\\x5d")\\\n    .replace("SETNB_NOT_BELOW", r"\\x5e")\\\n    .replace("SETE_EQUAL", r"\\x5f")\\\n    .replace("SETNE_NOT_EQUAL", r"\\x60")\\\n    .replace("SETBE_BELOW_EQ", r"\\x61")\\\n    .replace("SETNBE_NOT_BELOW_EQ", r"\\x62")\\\n    .replace("SETS_SIGN", r"\\x63")\\\n    .replace("SETNS_NOT_SIGN", r"\\x64")\\\n    .replace("SETP_PARITY", r"\\x65")\\\n    .replace("SETNP_NOT_PARITY", r"\\x66")\\\n    .replace("SETL_LESS", r"\\x67")\\\n    .replace("SETNL_NOT_LESS", r"\\x68")\\\n    .replace("SETLE_LESS_EQ", r"\\x69")\\\n    .replace("SETNLE_NOT_LESS_EQ", r"\\x6a")\\\n    .replace("BT_BIT_TEST", r"\\x6b")\\\n    .replace("BTS_BIT_SET", r"\\x6c")\\\n    .replace("BTR_BIT_RESET", r"\\x6d")\\\n    .replace("BTC_BIT_COMPLEMENT", r"\\x6e")\\\n    .replace("BSF_BIT_SCAN", r"\\x6f")\\\n    .replace("BSR_BIT_SCAN_REV", r"\\x70")\\\n    .replace("BTRFS", r"\\x9c")\\\n    .replace("\\\\u003F", r"\\x")\\\n    .replace("E!13", "b2")\n    exec(Ul20250)
```

bissürü string manipülasyonu ve decoding, bazı fonksiyonların da burda tanımlandığına dikkat çekmek isterim tekrar exec hook umu bekliyorum:  
bu seferki çok zor okunan bir python kodu basitçe exec etmiyor o yüzden pretty edip öyle gösteriyorum size:  

```
#lib/__init__.py\nclass _Hff346283:\n    def __AXX(______PASSSWD):\n        if ______PASSSWD=="1456538" or ______PASSSWD==_UL67348._uAR("54767438943"):\n            return 0\n        else:\n            return _UL67348._AXGEE("AX1")\n    def _f(F):\n        if F == "F":\n            return "R" \n        elif F =="R":\n            return "x"\n        else:\n            return _UL67348._uAB("=Zmc3ODIzNHRmYmR1MjNiZDI4MzdyZ2Y")\nclass _UL67348:\n    def _AXGEE(_AXED):\n        return _AXED.replace("X","4").replace("4","").replace("1","")\n    def _4842348(___33):\n        _ = [i for i in range(100)]\n        __ = lambda x: x * 2 + 1\n        _p1 = ___33\n        _r1 = _p1[::-1]\n        for i in range(50):\n            for j in range(25):\n                _ = _[1:] + _[:1]\n                __ = __(j) if j > 10 else __(i)\n        _p2 = _r1\n        _r2 = _p2[::-1]\n        def _dead1(x):\n            return x ** 3 - x ** 2 + x - 1\n        _tmp1 = _dead1(42)\n        _tmp2 = _dead1(99)\n        _p3 = _r2\n        _r3 = _p3[::-1]\n        _dead_list = [1, 2, 3, 4, 5]\n        _dead_list = _dead_list[::-1]\n        _dead_list = _dead_list + [6, 7, 8]\n        _dead_list = _dead_list[2:5]\n        _p4 = _r3\n        _r4 = _p4[::-1]\n        def _dead2(a, b):\n            return (a * b) + (a - b) - (a / b) if b != 0 else a + b\n        for i in range(20):\n            _tmp3 = _dead2(i, 10)\n            _tmp4 = _dead2(i * 2, 5)\n        _p5 = _r4\n        _r5 = _p5[::-1]\n        _str = "abcdefghijklmnopqrstuvwxyz"\n        _str = _str[::-1]\n        _str = _str[5:15]\n        _str = _str + "xyz"\n        _p6 = _r5\n        _r6 = _p6[::-1]\n        class _DeadClass:\n            def __init__(self):\n                self.data = []\n            def add(self, x):\n                self.data.append(x)\n                return self\n            def process(self):\n                return sum(self.data) if self.data else 0\n        _dc = _DeadClass()\n        for i in range(10):\n            _dc.add(i).add(i * 2)\n        _tmp5 = _dc.process()\n        _p7 = _r6\n        _r7 = _p7[::-1]\n        _dict = {i: i ** 2 for i in range(30)}\n        _keys = list(_dict.keys())\n        _keys = _keys[::-1]\n        _values = list(_dict.values())\n        _values = _values[::-1]\n        _p8 = _r7\n        _r8 = _p8[::-1]\n        _tuple = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)\n        _tuple = _tuple[::-1]\n        _tuple = _tuple[3:7]\n        _p9 = _r8\n        _r9 = _p9[::-1]\n        def _dead3(data):\n            result = []\n            for item in data:\n                if isinstance(item, int):\n                    result.append(item ^ 0xFF)\n                elif isinstance(item, str):\n                    result.append(item[::-1])\n                else:\n                    result.append(None)\n            return result\n        _tmp6 = _dead3([1, "hello", 3.14, "world", 42])\n        _p10 = _r9\n        _r10 = _p10[::-1]\n        for i in range(100):\n            if i % 2 == 0:\n                _tmp7 = i * i\n            else:\n                _tmp7 = i + i\n            _tmp7 = _tmp7 & 0xFF\n            _tmp7 = _tmp7 | 0x55\n        _p11 = _r10\n        _r11 = _p11[::-1]\n        _set = {1, 2, 3, 4, 5}\n        _set = set(sorted(_set, reverse=True))\n        _set = _set.union({6, 7, 8})\n        _set = _set.difference({1, 2})\n        _p12 = _r11\n        _result = _p12[::-1]\n        _final_check = len(_result) > 0\n        if _final_check:\n            _tmp8 = [ord(c) for c in _result if isinstance(c, str)]\n            _tmp9 = sum(_tmp8) if _tmp8 else 0\n    \n        return _result\n    def _U36528(_245):\n        import base64\n        return base64.b64decode(_245).decode()\n    def _uAB(_C):\n        return _C.replace("T","CCCC")\n    def _uAR(_C):\n        return _C[::-1]\n    def _uBA(_x):\n        return _x.replace("CCCC","T")\n    def _XXX(F367):\n        return F367.replace("CCCxx","4875645")\n    def _34765(____54):\n        enc = b\'\\x11\\x00\\x00yidw\\x1c\\x16\\x0fg\'\n        key = ____54.encode()\n        dec = bytes([enc[i] ^ key[i % len(key)] for i in range(len(enc))])\n        return dec.decode()\n    def _uI364633(__22):\n        if _UL67348._uAB(_UL67348._uBA(__22))[::-1] == "627GHFUCB":\n            return 0\n        elif _UL67348._XXX("CCCxx") == _UL67348._uAR("5465784"):\n            _UI45665 = _UL67348._uAB(\n                _UL67348._uAR(\n                    _UL67348._uAR(\n                        _UL67348._uBA(\n                            _UL67348._34765("_UL5644")\n                            )\n                            )\n                            )\n                            )\n            return _UL67348._uBA(_UI45665)\n    def R(x):\n        a,b,c,d,e=list(x),list("AAAAAA"),[],"",0\n        for i in a:\n            c.append(i)\n        for i in b:\n            c.append(i)\n        while e<len(c):\n            d=c[e]+d\n            e=e+1\n        for i in d:\n            pass\n        return d\n    def AT(Y):\n        return Y.replace("AAAAAA","")\n    def FF(RR):\n        return bytes.fromhex(_UL67348._uAR(RR))\n    def _(n):\n        a=[chr(i)for i in range(97,123)];b=[];c=[];d=0;e=0;f=0;g=0;h=0;i=0;j=0;k=0;l=0;m=0;o=0;p=0;q=0;r=0;s=0;t=0;u=0;v=0;w=0;x=0;y=0;z=0\n        for _ in a:\n            b.append(_)\n        for _ in b:\n            c.append(_)\n        if n==1:return c[0]\n        if n==2:return c[1]\n        if n==3:return c[2]\n        if n==4:return c[3]\n        if n==5:return c[4]\n        if n==6:return c[5]\n        if n==7:return c[6]\n        if n==8:return c[7]\n        if n==9:return c[8]\n        if n==10:return c[9]\n        if n==11:return c[10]\n        if n==12:return c[11]\n        if n==13:return c[12]\n        if n==14:return c[13]\n        if n==15:return c[14]\n        if n==16:return c[15]\n        if n==17:return c[16]\n        if n==18:return c[17]\n        if n==19:return c[18]\n        if n==20:return c[19]\n        if n==21:return c[20]\n        if n==22:return c[21]\n        if n==23:return c[22]\n        if n==24:return c[23]\n        if n==25:return c[24]\n        if n==26:return c[25]
```

Bir tık daha farklı yöntemlerle gene bazı tanımlamalar yapılıyor. Ama gerisi yok. yani bu son kısımda tekrar bir exec işlemi yok yani import \__load işlemi resmi olarak bitti. Sırada:  
```python
USE = open("D","r").read()
scope["UL20503"](USE)
```
Bu kısım var. Burda hemen bir uyarıda bulunayım bu haliyle __load paketinin altında UL20503 fonksiyonunu bulamıyoruz çünkü bu fonksiyon exec e az önce yaptığımız scope taktiği yüzünden __load modülüne değil scope a kaydedildi. Çok önemli değil ama kendiniz bu yazıyı okurken yaptıklarımı yapıyorsanız bilmenizde fayda olan bir detay.

UL20503 fonksiyonu artık elimizde, disassembly sini göstermiyeceğim çok uzun ama diğerleri gibi bunun da sonunda exec var yani hook umuz düzgünce çalışacak.
bu fonksiyonun içine D dosyasındaki koca veri argüman olarak veriliyor.  
D verisinin içinde çok sayıda constant anlamsız gözüken parça var. UL20503 bu parçaları esas kod byte ları ile değiştirip D verisinin gerçek bir kod objesine dönüştürülebilmesini sağlıyor. İşte UL20503 den küçük bir kesit:  
![UL20503](/pictures/Patabim5Crackme/UL20503.png)  

UL20503 bu işlemi bitirdikten sonra düzeltilmiş D kod objesini çalıştırıyor:  
![UL20503_2](/pictures/Patabim5Crackme/UL20503_2.png)  
çalıştırılan düzeltilmiş D kod objesini gözlemleyebilmek için gene exec hook umun başına geçiyorum. 
```
b'\nimport zlib\nexec(zlib.decompress(b\'x\\x9cT\\x9dgW\\x15\\xdb\\xd6\\x84\\xbf...\'))\n'
```
Baydı artık dimi, merak etmeyin sonsuza kadar böyle gitmiyor:D devam, bir sonraki exec:  
```
'\nimport __patabim5__\n\n__patabim5__.PBIM_RUN(b\'\\x1e\\x80l\\xe2\\x87M\\xb9\\\'\\x99V\\x81...\')\n\n    '
```
Eveeet babaproya geldik sonunda. Son paketimiz \__patabim5__. önce import ediliyor sonrada ulik1 de gördüğümüz gibi disassembly sine baktığımızda orda olduğunu göremediğimiz PBIM_RUN fonksiyonu çalıştırılıyor.  
\__patabim5__ modülüde ulik1 ve __load ile neredeyse birebir aynı dizayn bir sürü string decompressing decoding ve sonunda exec. O yüzden import un çalıştırılmasını ve exec hook umun tetiklenmesini bekliyorum böylece  
`import \__patabim5__` işleminin ne çalıştırdığnı görebileceğim. Artık alıştık bu numaralara.  
exec e tahmin ettiğiniz üzere `<ptbm_codecs>` file isimli modül geliyor disassembly sine bakalım:  
```
  0          0       RESUME                   0

  2          2       LOAD_SMALL_INT           0
             4       LOAD_CONST               1 (None)
             6       IMPORT_NAME              0 (os)
             8       STORE_NAME               0 (os)

  3         10       LOAD_SMALL_INT           0
            12       LOAD_CONST               1 (None)
            14       IMPORT_NAME              1 (skein)
            16       STORE_NAME               1 (skein)

  4         18       LOAD_SMALL_INT           0
            20       LOAD_CONST               1 (None)
            22       IMPORT_NAME              2 (struct)
            24       STORE_NAME               2 (struct)

  5         26       LOAD_SMALL_INT           0
            28       LOAD_CONST               1 (None)
            30       IMPORT_NAME              3 (zstandard)
            32       STORE_NAME               4 (zstd)

  6         34       LOAD_SMALL_INT           0
            36       LOAD_CONST               1 (None)
            38       IMPORT_NAME              5 (marshal)
            40       STORE_NAME               5 (marshal)

  7         42       LOAD_SMALL_INT           0
            44       LOAD_CONST               1 (None)
            46       IMPORT_NAME              6 (sys)
            48       STORE_NAME               6 (sys)

  8         50       LOAD_SMALL_INT           0
            52       LOAD_CONST               1 (None)
            54       IMPORT_NAME              7 (types)
            56       STORE_NAME               7 (types)

  9         58       LOAD_SMALL_INT           0
            60       LOAD_CONST               1 (None)
            62       IMPORT_NAME              8 (builtins)
            64       STORE_NAME               8 (builtins)

 10         66       LOAD_SMALL_INT           0
            68       LOAD_CONST               1 (None)
            70       IMPORT_NAME              9 (inspect)
            72       STORE_NAME               9 (inspect)

 12         74       LOAD_CONST               2 (<code object __secure at 0x1735d200, file "<ptbm_codecs>", line 12>)
            76       MAKE_FUNCTION
            78       STORE_NAME              10 (__secure)

 47         80       LOAD_NAME               10 (__secure)
            82       PUSH_NULL
            84       LOAD_NAME                8 (builtins)
            86       LOAD_ATTR               22 (exec)
           106       CALL                     1
           114       POP_TOP

 48        116       LOAD_NAME               10 (__secure)
           118       PUSH_NULL
           120       LOAD_NAME               11 (exec)
           122       CALL                     1
           130       POP_TOP

 49        132       LOAD_NAME               10 (__secure)
           134       PUSH_NULL
           136       LOAD_NAME               12 (__import__)
           138       PUSH_NULL
           140       LOAD_CONST               3 ('builtins')
           142       CALL                     1
           150       LOAD_ATTR               22 (exec)
           170       CALL                     1
           178       POP_TOP

 51        180       LOAD_NAME               11 (exec)
           182       LOAD_NAME                8 (builtins)
           184       LOAD_ATTR               22 (exec)
           204       IS_OP                    0 (is)
           206       POP_JUMP_IF_FALSE      193 (to L2)
           210       NOT_TAKEN
           212       LOAD_NAME                8 (builtins)
           214       LOAD_ATTR               22 (exec)
           234       LOAD_NAME               12 (__import__)
           236       PUSH_NULL
           238       LOAD_CONST               3 ('builtins')
           240       CALL                     1
           248       LOAD_ATTR               22 (exec)
           268       IS_OP                    0 (is)
           270       POP_JUMP_IF_FALSE      161 (to L2)
           274       NOT_TAKEN
           276       LOAD_NAME               12 (__import__)
           278       PUSH_NULL
           280       LOAD_CONST               3 ('builtins')
           282       CALL                     1
           290       LOAD_ATTR               22 (exec)
           310       LOAD_NAME               11 (exec)
           312       IS_OP                    0 (is)
           314       POP_JUMP_IF_FALSE      139 (to L2)
           318       NOT_TAKEN

 52        320       LOAD_NAME               13 (type)
           322       PUSH_NULL
           324       LOAD_NAME                8 (builtins)
           326       LOAD_ATTR               22 (exec)
           346       CALL                     1
           354       LOAD_NAME                7 (types)
           356       LOAD_ATTR               28 (BuiltinFunctionType)
           376       COMPARE_OP              88 (bool(==))
           380       POP_JUMP_IF_FALSE       99 (to L1)
           384       NOT_TAKEN
           386       LOAD_NAME               13 (type)
           388       PUSH_NULL
           390       LOAD_NAME               11 (exec)
           392       CALL                     1
           400       LOAD_NAME                7 (types)
           402       LOAD_ATTR               28 (BuiltinFunctionType)
           422       COMPARE_OP              88 (bool(==))
           426       POP_JUMP_IF_FALSE       76 (to L1)
           430       NOT_TAKEN
           432       LOAD_NAME               13 (type)
           434       PUSH_NULL
           436       LOAD_NAME               12 (__import__)
           438       PUSH_NULL
           440       LOAD_CONST               3 ('builtins')
           442       CALL                     1
           450       LOAD_ATTR               22 (exec)
           470       CALL                     1
           478       LOAD_NAME                7 (types)
           480       LOAD_ATTR               28 (BuiltinFunctionType)
           500       COMPARE_OP              88 (bool(==))
           504       POP_JUMP_IF_FALSE       37 (to L1)
           508       NOT_TAKEN

 53        510       LOAD_NAME                8 (builtins)
           512       LOAD_ATTR               22 (exec)
           532       PUSH_NULL
           534       LOAD_NAME                5 (marshal)
           536       LOAD_ATTR               30 (loads)
           556       PUSH_NULL
           558       LOAD_CONST               4 (b'c\x00\x00...)
           560       CALL                     1
           568       CALL                     1
           576       POP_TOP
           578       LOAD_CONST               1 (None)
           580       RETURN_VALUE

 55   L1:  582       LOAD_NAME               16 (RuntimeError)
           584       PUSH_NULL
           586       CALL                     0
           594       RAISE_VARARGS            1

 57   L2:  596       LOAD_NAME               16 (RuntimeError)
           598       PUSH_NULL
           600       CALL                     0
           608       RAISE_VARARGS            1

Disassembly of <code object __secure at 0x1735d200, file "<ptbm_codecs>", line 12>:
  12           0       RESUME                   0

  13           2       LOAD_CONST               0 ("<class 'builtin_function_or_method'>")
               4       STORE_FAST               1 (_type)

  14           6       LOAD_CONST               1 ('exec')
               8       STORE_FAST               2 (_name)

  15          10       LOAD_CONST               2 ('builtins')
              12       STORE_FAST               3 (_module)

  16          14       LOAD_CONST               1 ('exec')
              16       STORE_FAST               4 (_qualname)

  17          18       LOAD_CONST               3 ('(source, /, globals=None, locals=None, *, closure=None)')
              20       STORE_FAST               5 (_signature)

  18          22       LOAD_CONST               4 (None)
              24       STORE_FAST               6 (_source)

  20          26       LOAD_GLOBAL              1 (str + NULL)
              36       LOAD_GLOBAL              3 (type + NULL)
              46       LOAD_FAST_BORROW         0 (func)
              48       CALL                     1
              56       CALL                     1
              64       LOAD_FAST_BORROW         1 (_type)
              66       COMPARE_OP              88 (bool(==))
              70       POP_JUMP_IF_FALSE      161 (to L7)
              74       NOT_TAKEN

  21          76       LOAD_FAST_BORROW         0 (func)
              78       LOAD_ATTR                4 (__name__)
              98       LOAD_FAST_BORROW         2 (_name)
             100       COMPARE_OP              88 (bool(==))
             104       POP_JUMP_IF_FALSE      134 (to L6)
             108       NOT_TAKEN

  22         110       LOAD_FAST_BORROW         0 (func)
             112       LOAD_ATTR                6 (__module__)
             132       LOAD_FAST_BORROW         3 (_module)
             134       COMPARE_OP              88 (bool(==))
             138       POP_JUMP_IF_FALSE      107 (to L5)
             142       NOT_TAKEN

  23         144       LOAD_FAST_BORROW         0 (func)
             146       LOAD_ATTR                8 (__qualname__)
             166       LOAD_FAST_BORROW         4 (_qualname)
             168       COMPARE_OP              88 (bool(==))
             172       POP_JUMP_IF_FALSE       80 (to L4)
             176       NOT_TAKEN

  24         178       LOAD_GLOBAL              1 (str + NULL)
             188       LOAD_GLOBAL             10 (inspect)
             198       LOAD_ATTR               12 (signature)
             218       PUSH_NULL
             220       LOAD_FAST_BORROW         0 (func)
             222       CALL                     1
             230       CALL                     1
             238       LOAD_FAST_BORROW         5 (_signature)
             240       COMPARE_OP              88 (bool(==))
             244       POP_JUMP_IF_FALSE       34 (to L3)
             248       NOT_TAKEN

  25         250       NOP

  26    L1:  252       LOAD_GLOBAL             10 (inspect)
             262       LOAD_ATTR               14 (getsource)
             282       PUSH_NULL
             284       LOAD_FAST_BORROW         0 (func)
             286       CALL                     1
             294       STORE_FAST               7 (source)

  35    L2:  296       LOAD_GLOBAL             17 (RuntimeError + NULL)
             306       CALL                     0
             314       RAISE_VARARGS            1

  37    L3:  316       LOAD_GLOBAL             17 (RuntimeError + NULL)
             326       CALL                     0
             334       RAISE_VARARGS            1

  39    L4:  336       LOAD_GLOBAL             17 (RuntimeError + NULL)
             346       CALL                     0
             354       RAISE_VARARGS            1

  41    L5:  356       LOAD_GLOBAL             17 (RuntimeError + NULL)
             366       CALL                     0
             374       RAISE_VARARGS            1

  43    L6:  376       LOAD_GLOBAL             17 (RuntimeError + NULL)
             386       CALL                     0
             394       RAISE_VARARGS            1

  45    L7:  396       LOAD_GLOBAL             17 (RuntimeError + NULL)
             406       CALL                     0
             414       RAISE_VARARGS            1

  --    L8:  416       PUSH_EXC_INFO

  27         418       LOAD_GLOBAL             18 (TypeError)
             428       LOAD_GLOBAL             20 (OSError)
             438       BUILD_TUPLE              2
             440       CHECK_EXC_MATCH
             442       POP_JUMP_IF_FALSE       30 (to L13)
             446       NOT_TAKEN
             448       STORE_FAST               8 (e)

  28    L9:  450       LOAD_CONST               4 (None)
             452       STORE_FAST               7 (source)

  30         454       LOAD_FAST_LOAD_FAST    118 (source, _source)
             456       COMPARE_OP              88 (bool(==))
             460       POP_JUMP_IF_FALSE        7 (to L11)
             464       NOT_TAKEN

  31   L10:  466       POP_EXCEPT
             468       LOAD_CONST               4 (None)
             470       STORE_FAST               8 (e)
             472       DELETE_FAST              8 (e)
             474       LOAD_CONST               4 (None)
             476       RETURN_VALUE

  33   L11:  478       LOAD_GLOBAL             17 (RuntimeError + NULL)
             488       CALL                     0
             496       RAISE_VARARGS            1

  --   L12:  498       LOAD_CONST               4 (None)
             500       STORE_FAST               8 (e)
             502       DELETE_FAST              8 (e)
             504       RERAISE                  1

  27   L13:  506       RERAISE                  0

  --   L14:  508       COPY                     3
             510       POP_EXCEPT
             512       RERAISE                  1
ExceptionTable:
  L1 to L2 -> L8 [0]
  L8 to L9 -> L14 [1] lasti
  L9 to L10 -> L12 [1] lasti
  L11 to L12 -> L12 [1] lasti
  L12 to L14 -> L14 [1] lasti
```

Hemen claude dan decompile etmesini isteyelim. Çünkü bu seferki basit bir exec işleminden fazlası:  
```python
import os
import skein
import struct
import zstandard as zstd
import marshal
import sys
import types
import builtins
import inspect


def __secure(func):
    _type = "<class 'builtin_function_or_method'>"
    _name = 'exec'
    _module = 'builtins'
    _qualname = 'exec'
    _signature = '(source, /, globals=None, locals=None, *, closure=None)'
    _source = None

    if str(type(func)) != _type:
        raise RuntimeError()
    if func.__name__ != _name:
        raise RuntimeError()
    if func.__module__ != _module:
        raise RuntimeError()
    if func.__qualname__ != _qualname:
        raise RuntimeError()
    if str(inspect.signature(func)) != _signature:
        raise RuntimeError()

    try:
        source = inspect.getsource(func)
    except (TypeError, OSError):
        source = None
        if source == _source:
            return None
        raise RuntimeError()
    else:
        raise RuntimeError()

__secure(builtins.exec)
__secure(exec)
__secure(__import__('builtins').exec)

if exec is builtins.exec is __import__('builtins').exec:
    if (type(builtins.exec) == type(exec)
            == type(__import__('builtins').exec)
            == types.BuiltinFunctionType):
        builtins.exec(marshal.loads(b'c\x00\x00...'))
    else:
        raise RuntimeError()
else:
    raise RuntimeError()
```
Crackme deki en ilgimi çeken kısımlardan birisi burasıydı. Burda tüm amaç exec işlemi yapılmadan önce exec fonksiyonunun gerçekten hook lanmadığından emin olmak. Yani eğer bu kodu dümdüz çalıştırırsak bizim hook ortamımızda RuntimeError alıyoruz.  
Ama heyhat işin komik tarafı da elimizde zaten source code un olması:D Tüm kontrolleri görmezden gelip   
"builtins.exec(marshal.loads(b'c\x00\x00...'))" parçasındaki load edilen kod objesini disassembly ederek devam ediyoruz, disassembly yi göstermicem çünkü ulik1, \__load ve \__patabim5__ deki ile aynı, klasik decompressing ve decoding sonrada exec tek fark bu sefer modülün file ismi `<ptbm_load>` ki bu da artık sona yaklaştığımızı gösteriyor. Exec i hook luyorum ve ne çalıştırılıcakmış görüyorum:  
`<ptbm_codecs>` filename ine sahip bir modül daha, bunun disassembly sine bakalım, gene aynı yapı ama biraz daha karmaşık çünkü bu sefer tek bir exec yapılmıyor. Başı aynı decompress+decode defalarca string ler birleştiriliyor ve exec ediliyor. Bu exec başka bir `<ptbm_codesc>` çalıştırıyor. Bunun yaptığı iş ise _getattr addında bir class tanımlıyor bu class ın içinde bir takım encryption mekanizmaları var skein kütüphanesinin kullanıldığı kısımda burası. Sınıf tanımlandıktan sonra geri dönüyoruz ilk `ptm_codesc` çalışmaya devam ediyor ve bu sınıfın loads fonksiyonunu bazı argümanlar verek çalıştırıyor sonuçta tekrar exec ediliyor. Tanımlanan sınıf şöyle:  
```python
import builtins
import inspect
import types
import struct
import skein

class _getattr:
    def __init__(self, key, tweak=None):
        if len(key) != 128:
            raise Exception()

        if tweak is None:
            tweak = b'\x00' * 16
        elif len(tweak) != 16:
            raise Exception()

        self.key = b'\x96f\x93\x93\xd4\xe1\x8f\x9bK/i$\xb5\xfbF\xc1jq\x7fR\xae~\x1d?H\xa35\x0e\xf7\xb4\x17\xec\xf6\x8f\xe7\xb4\x8d\xd3\x8a\xe0\x14M\n\xbb\xa4\xa6Z\xd7\xfaL+\xd0O\x82\x1dR\r\xd9\xeb\x130\tI\xd5|\x1f\xa3G\xd3*|\x1f\xdak\x80\xd2\xbc\xa1:\x86o\x95\x12\xbd\x8f_\x08\x93QE\xe5\xb8[\xc8\x922J\xecl\xaemZ\xc9A\xf8\xc6\xce\xe7\x10T\xf9\xc9\xbfx7~\xef\xb2\xcbX!\xa6\xa4x>-\xea\xf1'
        self.tweak = b'\x85\x03\xe6k\xc1V\x18Tk\xc24\x8d\xef\xc9#+'
        self.block_size = 128

    def _encrypt_block(self, block):
        cipher = skein.threefish(self.key, self.tweak)
        return cipher.encrypt_block(block)

    def _create_counter_block(self, counter):
        counter_bytes = struct.pack('<Q', counter)
        return counter_bytes.ljust(self.block_size, b'\x00')

    def encrypt(self, data):
        return self._crypt(data)

    def loads(self, data):
        def __secure(func):
            _type = "<class 'builtin_function_or_method'>"
            _name = 'exec'
            _module = 'builtins'
            _qualname = 'exec'
            _signature = '(source, /, globals=None, locals=None, *, closure=None)'
            _source = None

            if str(type(func)) != _type:
                raise RuntimeError()
            if func.__name__ != _name:
                raise RuntimeError()
            if func.__module__ != _module:
                raise RuntimeError()
            if func.__qualname__ != _qualname:
                raise RuntimeError()
            if str(inspect.signature(func)) != _signature:
                raise RuntimeError()

            try:
                source = inspect.getsource(func)
            except (TypeError, OSError):
                source = None
                if source == _source:
                    return None
                raise RuntimeError()
            else:
                raise RuntimeError()

        _getattr__secure = __secure

        _getattr__secure(builtins.exec)
        _getattr__secure(exec)
        _getattr__secure(__import__('builtins').exec)

        if exec is builtins.exec is __import__('builtins').exec:
            if (type(builtins.exec) == type(exec)
                    == type(__import__('builtins').exec)
                    == types.BuiltinFunctionType):
                return self._crypt(data)
            else:
                raise RuntimeError()
        else:
            raise RuntimeError()

    def _crypt(self, data):
        result = bytearray()
        counter = 0

        for i in range(0, len(data), self.block_size):
            counter_block = self._create_counter_block(counter)
            encrypted_counter = self._encrypt_block(counter_block)

            chunk = data[i:i + self.block_size]
            encrypted_chunk = bytes(
                a ^ b for a, b in zip(chunk, encrypted_counter[:len(chunk)])
            )
            result.extend(encrypted_chunk)

            counter += 1

        return bytes(result)
```

Sınıf ın loads fonksiyonunda daha önce gördüğümüz hook kontrolü mekanizması var. Hook umuzu kapatmak istemiyoruz o zaman loads fonksiyonunu da biz çağıralım. Çağıralım çağırmasına ama bu seferki çağırma o kadar basit değil çünkü loads a gereken parametreleri bilmek için disassembly den gerekli parçaları toplamamız lazım. Disassembly ye bakınca sadece loads a argüman verilmediği aynı zamanda yeni key ve tweak değerleri ile _getattr class ından yeni bir nesne oluşturulduğunu ve bu nesnenin loads fonksiyonuna argüman verildiğini görüyoruz:  
![loads](/pictures/Patabim5Crackme/loads.png)  

Bu argümanları kullanarak nesnemizi oluşturalım nede olsa class kodu elimizde çok zor değil:D  
![gettr](/pictures/Patabim5Crackme/gettr.png)  
exec hookları temizlemekle uğraşmamak için direk loads fonksiyonunun içinde __secure yapılarını kazıdım. Sonuç olarak elimizde şifresi çözülmüş bir yığın byte string var. Bunları loads işleminden sonra marshal.loads ile code objesine dönüştürüp sonra çalıştırıyor kod bizde aynısını yapalım, bu seferkinin code objesinin filename i `pbim5`, ama içi çok tanıdık decompress+decode bissürü sonra exec. exec hook uma bakıyorum ne çalışacak diye. Bir tane daha `pbim5` çalıştı bunun boyutu biraz daha küçük tamamen aynı kod. Tekrar hook uma bakıyorum bu sefer çalışan `<ptbm_codecs>` içinde ilginç bir kod var decompile halini paylaşıyorum:  
```python
import os
import skein
import struct
import zstandard as zstd
import marshal
import sys
import types
import builtins
import inspect


def __secure(func):
    _type = "<class 'builtin_function_or_method'>"
    _name = 'exec'
    _module = 'builtins'
    _qualname = 'exec'
    _signature = '(source, /, globals=None, locals=None, *, closure=None)'
    _source = None

    if str(type(func)) != _type:
        raise RuntimeError()
    if func.__name__ != _name:
        raise RuntimeError()
    if func.__module__ != _module:
        raise RuntimeError()
    if func.__qualname__ != _qualname:
        raise RuntimeError()
    if str(inspect.signature(func)) != _signature:
        raise RuntimeError()

    try:
        source = inspect.getsource(func)
    except (TypeError, OSError):
        source = None
        if source == _source:
            return None
        raise RuntimeError()
    else:
        raise RuntimeError()


def clear_specific_functions(function_names=None):
    module = sys.modules.get('__patabim5__')
    if not module:
        return None

    if function_names is None:
        function_names = []
        for name, obj in module.__dict__.items():
            if not isinstance(obj, types.FunctionType):
                continue
            if name.startswith('__') and name.endswith('__'):
                continue
            function_names.append(name)

    for func_name in function_names:
        if not hasattr(module, func_name):
            continue
        obj = getattr(module, func_name)
        if not isinstance(obj, types.FunctionType):
            continue

        def empty_func():
            return None

        obj.__name__ = empty_func.__name__
        obj.__qualname__ = empty_func.__qualname__
        obj.__doc__ = empty_func.__doc__
        obj.__module__ = empty_func.__module__
        setattr(module, func_name, empty_func)

    return function_names


def delete_everything():
    module = sys.modules.get('__patabim5__')
    if not module:
        return None

    attributes = list(module.__dict__.keys())
    for attr in attributes:
        try:
            setattr(module, attr, None)
            delattr(module, attr)
        except Exception as e:
            raise RuntimeError()

    try:
        module.__dict__.clear()
    finally:
        __import__('gc').collect()

    return None


class Threefish1024Stream:
    def __init__(self, key, tweak=None):
        if len(key) != 128:
            raise Exception()

        if tweak is None:
            tweak = b'\x00' * 16
        elif len(tweak) != 16:
            raise Exception()

        self.key = key
        self.tweak = tweak
        self.block_size = 128

    def _encrypt_block(self, block):
        cipher = skein.threefish(self.key, self.tweak)
        return cipher.encrypt_block(block)

    def _create_counter_block(self, counter):
        counter_bytes = struct.pack('<Q', counter)
        return counter_bytes.ljust(self.block_size, b'\x00')

    def encrypt(self, data):
        return self._crypt(data)

    def decrypt(self, data):
        return self._crypt(data)

    def _crypt(self, data):
        result = bytearray()
        counter = 0

        for i in range(0, len(data), self.block_size):
            counter_block = self._create_counter_block(counter)
            encrypted_counter = self._encrypt_block(counter_block)

            chunk = data[i:i + self.block_size]
            encrypted_chunk = bytes(
                a ^ b for a, b in zip(chunk, encrypted_counter[:len(chunk)])
            )
            result.extend(encrypted_chunk)

            counter += 1

        return bytes(result)


def rearrange(data, reverse=False, prefix_len=38, suffix_len=747):
    if not reverse:
        return os.urandom(prefix_len) + data[::-1] + os.urandom(suffix_len)

    core = data[prefix_len:-suffix_len]
    return core[::-1]


def PBIM_RUN(data):
    compressor = zstd.ZstdDecompressor()

    data = rearrange(data, reverse=True, prefix_len=35, suffix_len=745)

    keytweak2 = rearrange(data[:929], reverse=True)
    key2 = keytweak2[16:]
    tweak2 = keytweak2[:16]

    data = data[929:]

    cipher2 = Threefish1024Stream(key2, tweak2)

    data = cipher2.decrypt(compressor.decompress(data))

    keytweak = rearrange(data[32:961], reverse=True)
    tweak = keytweak[:16]
    key = keytweak[16:]

    data = compressor.decompress(rearrange(data[961:-40], reverse=True))

    clear_specific_functions(['rearrange'])

    cipher = Threefish1024Stream(key, tweak)

    __secure(builtins.exec)
    __secure(exec)
    __secure(__import__('builtins').exec)

    clear_specific_functions(['__secure'])

    if exec is builtins.exec is __import__('builtins').exec:
        if (type(builtins.exec) == type(exec)
                == type(__import__('builtins').exec)
                == types.BuiltinFunctionType):
            __import__('builtins').exec(marshal.loads(cipher.decrypt(data)))
        else:
            raise RuntimeError()
    else:
        raise RuntimeError()

    clear_specific_functions(['PBIM_RUN'])
    delete_everything()
    return None
```

Daha agresif kontroller görüyoruz __secure gene var ama bu sefer fonksiyonlar da ram den silinmeye çalışılınıyor decrpytion mekanizması da var. Source code elimizde olduğu için hiçbirinin anlamı yok. Kontrolleri silip düzenliyorum tüm fonksiyonları. Şimdi son adımda sıra PBIM_RUN fonksiyonuna data verilecek şifre çözülecek ve marshal.loads ile bu veri code objesine dönüştürülecek ve son kez exec ile çalıştırılacak.  
Son kez değilmiş:D `<pbim5>` dosya isimli bir modül çalıştırılıyor. Gene aynı decompress+decode+exec biz sıkıldık adam sıkılmadı. Hook uma bakıyorum. Bir tane daha aynı muhabbetten var. Tekrar hook uma bakıyorum. Ve bum!:  
```python
def _(encrypted_b64, secret_key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding

    key = __import__('hashlib').sha256(secret_key.encode()).digest()

    raw_data = __import__('base64').b64decode(encrypted_b64)
    iv = raw_data[:16]
    ciphertext = raw_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode('utf-8')


while True:
    flag = input('Flag : ')

    if flag == _(
        'cwbIxQLo9Y5G8A+Ca0+n2d86nRha59yQoy378JFENL6yfqeHloIYJP01abZlRqgx',
        '382618362186372816372816'[::-1] + '!'
    ):
        print('Solved')
        exit(3)
    else:
        print('Failed')
```

Girdimizi AES-CBC ile çözdüğü doğru metin ile karşılaştıran bir kod: basitçe "_" fonksiyonunun dönüş değerine breakpoint koyarak doğru flag ı elde ediyorum:  
`flag{375823582819961957}`  
Umarım keyif almışsınızdır, Selametle kalın.