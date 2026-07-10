---
layout: post
title: "Zombie Process leri tanıyalım"
date: 2026-07-10
---

# Zombie Process ler nedir?
Windows Kernel i bir process sonlandırıldığında o Process in kullandığı belleği boşaltır, handle ları kapatır. Ve her process için tuttuğu [EPROCESS](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess#eprocess) objesini de siler. Ama işte bazen silemez. Bu silemediği durumlarda hiçbir kod çalıştırmayan, belleği olmayan amaçsız bir process objemiz kalır elimizde. İşte bu objenin ifade ettiği process e Zombie Process denir.

## Bir Zombie Process nasıl oluşur?
Bir Zombie Process oluşturmak için process kapanmadan önce o process in handle ını tutup bırakmamamız yani CloseHandle ile kapatmamamız lazım. Hedef Process in handle ını alıyoruz sonra hedef process i yani zombi ye çevireceğimiz process i kapatıyoruz. Artık hedef process in kernel tarafında EPROCESS objesi, Object Manager'ın tuttuğu referans sayısı sıfıra düşmeden silinmeyecek. Böylece kapanmasına rağmen kernel de var olan bir process yani zombie process yaratmış olacaz.

## Zombie Process yapımı
Basitçe bir zombie process yapmak için kapatmadan önce bir process in handle ını tutmak olacak. Bunun için basit bir kod yazalım:
```c
#include <windows.h>
#include <stdio.h>

int main(void) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    WCHAR name[] = L"mspaint.exe";

    BOOL ok = CreateProcessW(NULL, name, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    if (!ok) {
        printf("CreateProcess basarisiz. GetLastError = %lu\n", GetLastError());
        return 1;
    }

    printf("Paint olusturuldu. PID = %lu, hProcess = %p, hThread = %p\n",
           pi.dwProcessId, pi.hProcess, pi.hThread);


    if (!TerminateProcess(pi.hProcess, 0)) {
        printf("TerminateProcess basarisiz. GetLastError = %lu\n", GetLastError());
        return -1;
    }

    getchar();
    return 0;
}
```

mspaint System32 de bulunan Windows un yerleşik pain uygulaması onu en normal şekilde CreateProcess api si ile çalıştırıyoruz. Sonra da terminate ediyoruz. Bu koddaki yanlış pi.hProcess ve pi.hThread handle ını kapatmamamız. Bize söylenen bu. Peki bu handle ları kapatmamanın bedeli ne. İşte şimdi bunu gözlemleme zamanı.

Programı derleyip çalıştıralım. getchar fonksiyonu sayesinde program kapanmayacak bu önemli aksi takdirde kernel bizim bilerek kapatmadığımız handle ları bizim yerimize kapatır.

![image1](/pictures/zombie_processes/image1.png)
WinDbg üzerinden local kernel debugging i açtım. Şimdi kapanan mspaint.exe process sinin hala kernel tarafında tutulduğunu kanıtlamak için "!process 24a4" komutunu çalıştıralım: (WinDbg sayı olarak hex kabul edeceği için 9380 in hexadecimal karşılığı olan 24a4 ü kullandım)

```
lkd> !process 24a4
Searching for Process with Cid == 24a4
PROCESS ffffe28ff5408080
    SessionId: none  Cid: 24a4    Peb: 7fa096b000  ParentCid: 54f8
    DirBase: 442d01000  ObjectTable: 00000000  HandleCount:   0.
    Image: mspaint.exe
    VadRoot 0000000000000000 Vads 0 Clone 0 Private 16. Modified 11. Locked 0.
    DeviceMap 0000000000000000
    Token                             ffffd189701f1060
    ElapsedTime                       00:06:05.394
    UserTime                          00:00:00.000
    KernelTime                        00:00:00.000
    QuotaPoolUsage[PagedPool]         0
    QuotaPoolUsage[NonPagedPool]      0
    Working Set Sizes (now,min,max)  (17, 50, 345) (68KB, 200KB, 1380KB)
    PeakWorkingSetSize                504
    VirtualSize                       0 Mb
    PeakVirtualSize                   2097158 Mb
    PageFaultCount                    528
    MemoryPriority                    BACKGROUND
    BasePriority                      8
    CommitCharge                      20
    Job                               ffffe28feb111060

No active threads
        THREAD ffffe28fdc098080  Cid 24a4.4920  Teb: 0000000000000000 Win32Thread: 0000000000000000 TERMINATED
```

Göreceğiniz üzere kernel tarafında hala 9380 pid li bir process in objesi var. Aynı şekilde en aşağıda göreceğiniz üzere thread in de objesi duruyor keza onunda handle ını close etmemiştik. Tüm bunların sebebi handle ları kapatmamış olmamız. Handle ları kapatmadığımız için hala bu objeler referans ediliyor bu sebeple kernel onları silmiyor. Bu yüzden de bellekte bu gereksiz process ve thread objelerini tutmuş oluyoruz. Bellekte boş yere duran EPROCESS objelerinin açıkladığı process lere zombie process diyoruz.

Süreci User-Space den takip etmek için c ile claude a yazdırdığım [şu](https://github.com/SemsYapar/ZombieScanner) programı kullanabiliriz:

Programı çalıştırdığımızda arka planda hala dene.exe çalışıyorken mspaint i zombie process olarak görebiliyoruz:
![image2](/pictures/zombie_processes/image2.png)

dene.exe yi kapatınca kernel onun kapatmadığı handle ları da kapattığı için artık böyle bir zombie process kalmıyor.

Umarım anlaşılır olmuştur <3, selametle kalın.