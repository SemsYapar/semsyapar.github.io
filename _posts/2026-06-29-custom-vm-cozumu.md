---
layout: post
title: "Custom VM Çözümü"
categories: blue
date: 2026-06-29
---

# Giriş

[TurkHackTeam](https://www.turkhackteam.org/konular/crack-me-zorluk-9-8-10.2083682) de 'Egemen.' tarafından yapılıp paylaşılan crackme nin analizini içeren bir yazı olacak.

## Açıklama
Ne yazıkki crackme yi çözüp valid key üretemedim. Ama bunun sebebi kanımca crackme nin çözülebilir olarak yapılmamasından kaynaklanıyor.

## protected_crackme.exe ye ilk bakış

Exe nin section larını incelediğimizde soru açıklamasında geçen "lopinki" kelimesinin belliki bir kısaltması olan .lpk adlı özel bir section var. section un ilk byte ları lopinki "LOPNLPK1" adlı bir imza ile başlıyor. AMD64 mimarisi ile derlenmiş.

## 1. Katman

Programın giriş fonksiyonuna baktığımızda bizi bu aralar görmeye çok aşina olduğumuz basic bir api hashing sistemi karşılıyor.

```asm
    mov r13,8B71B8BA2A7F646A
    mov rcx,DBC5C95C77A7D0E6
    mov rdx,r13
    call <protected_crackme.module_resolver>
    mov rdx,r13
    mov rcx,3EDD09E5C1C1865
    mov rdi,rax
    call <protected_crackme.module_resolver>
    mov rdx,r13
    mov rcx,B05BED86338694F2
    mov rbx,rax
    call <protected_crackme.module_resolver>
    mov rsi,rax
```

module_resolver fonsksiyonu peb->ldr->InLoadOrderModuleList üzerinden windows loader ının process e yüklediği ntdll, kernelbase gibi module leri dolanıyor ve yaptığı hash işlemi ile istediği module un adresini dönüyor

Module adresini çektik, şimdi o module lerden istediğimiz fonksiyonların adreslerini çekme zamanı

```
    mov rdx,47EFE0420BD9306C
    mov rcx,rdi
    call <protected_crackme.api_resolver>
    xor r9d,r9d
    mov qword ptr ss:[rsp+2D0],rax
    mov r8,r13
    mov rdx,4C35CEDD08FFB6FD
    mov rcx,rdi
    call <protected_crackme.api_resolver>
    xor r9d,r9d
    mov r8,r13
```

api_resolver hedef module ün export table ına gidiyor, fonksiyonlarını hash liyip istediği hash ile kıyaslıyor ve fonksiyonun adresini dönüyor  
Bu şekilde elde edilen fonksiyon adresleri şunlar:  
VirtualAlloc, VirtualFree, VirtualProtect, LoadLibraryA, GetProcAddress, FlushInstructionCache, RtlAddFunctionTable  
Bunlardan son ikisi daha önce pek görmediğim fonksiyonlardı bu program ile birlikte tanımış oldum.

```
    mov rax,qword ptr gs:[60] //peb
    xor r9d,r9d
    mov ebx,r9d
    mov edx,r9d
    mov r11d,r9d
    mov r10,qword ptr ds:[rax+10] // peb->ImageBaseAddress
    mov eax,dword ptr ds:[r10+3C] // dos->e_lfanew
    movzx ecx,word ptr ds:[rax+r10+14] // nt->SizeOfOptionalHeader
    movzx r8d,word ptr ds:[rax+r10+6] // nt->NumberOfSections
    add rcx,20
    mov esi,dword ptr ds:[rax+r10+28] //OptionalHeader->AddressOfEntryPoint
    add rcx,rax
    cmp r9w,r8w
    jae protected_crackme.7FF607C24B26
    lea rax,qword ptr ds:[rcx+r10]
    mov edi,r8d
    cmp byte ptr ds:[rax-8],2E // '.'
    mov r8d,dword ptr ds:[rax+4] // sections[i]->VirtualAddress
    mov ecx,dword ptr ds:[rax] // sections[i]->VirtualSize
    jne protected_crackme.7FF607C248FC
    cmp byte ptr ds:[rax-7],6C // 'l'
    jne protected_crackme.7FF607C248FC
    cmp byte ptr ds:[rax-6],70 // 'p'
    jne protected_crackme.7FF607C248FC
    cmp byte ptr ds:[rax-5],6B // 'k'
    jne protected_crackme.7FF607C248FC
    cmp byte ptr ds:[rax-4],r9b
    jne protected_crackme.7FF607C248FC
    lea rbx,qword ptr ds:[r10+r8]
    test rdx,rdx
    jne protected_crackme.7FF607C24915
```

Gene peb aracılığı ile main module ümüze ulaşıyoruz ve tüm section larımızın tek tek isimlerine bakıyoruz. '.lpk' ismindeki özel section umuzu arıyoruz.  
Bulunca ilk ve 4. byte ını kontrol ediyoruz bu section un. Eğer [0] == 'L' ve [3] == 'N' ise devam ediyoruz.

Şimdi sıra kişisel olarak hoşuma giden code section hash hesaplama yerinde:
```
    movzx eax,byte ptr ds:[rdx+r9]
    inc r9
    xor r8,rax
    imul r8,rcx
    cmp r9,r11
    jb protected_crackme.7FF7C3AF4960
```
Yukarda .lpk section unu aradığımız döngüde özel olarak ilk section un virtualAddress ve rawSize bilgilerini çekiyoruz. Bu bilgileri kullanarak hash basit bir hash döngüsü çalıştırıyoruz bu sayede code section da yapılan patch ve software breakpoint ler yakalanıyor.

```
    call <protected_crackme.code_section_hash_checker>
    mov rbx,qword ptr ds:[rax]
    mov r8,qword ptr ds:[rax+8]
    test rbx,rbx
    je protected_crackme.7FF7C3AF4B26
```

Hash imiz bir sayısal değiştirme algoritmasından geçtikten sonra bu fonksiyon onu kontrol ediyor. Eğer hash doğru ise .lpk bölümünü çözüyor değilse je branch i ile programa veda ediyoruz. Bu kısmı geçebilmek için o ana kadar koyduğum tüm software breakpoint leri kapattım. Patch zaten yapmamıştım.

code_section_hash_checker fonksiyonu eğer code section bozulmamışsa .lpk section unu çözüyor. ve onu loader fonksiyonuna iletiyor.
```
00007FF7C3AF4AE7 | E8 64E2FFFF              | call <protected_crackme.call_embaded_pe_and_map>   |
```

Bu fonksiyonun yaptığı şey esasen LoadLibrary fonksiyonunun yaptığı şeyi daha gürültüsüz(Windows api si çalıştırmadan) yapmak. Bellekte yer açıyor ve .lpk den çıkan Exe yi bu belleğe elle load ediyor. Exe load edilirken api_resolver fonksiyonlarından çözdüğümüz windows api leri çalışıyor buralar çok basmakalıp olduğu için girmedim sadece dikkatimi CPU yu yeni bölgeye hazırlamak için çağrılan FlushInstructionCache ve yeni binary mizin exception table ını mevcut process e yüklemek için çağrılann RtlAddFunctionTable çekti. Ama bu yapılan manuel load işleminde Relocation Table kullanılmıyor yani bundan sonra üzerinde duracağımız tüm adresler hep aynı kalacak diyebiliriz.

```
    call rbp // VirtualFree
    cmp byte ptr ss:[rsp+60],0
    je protected_crackme.7FF7C3AF4B26
    movups xmm0,xmmword ptr ss:[rsp+70]
    psrldq xmm0,8
    movq rax,xmm0
    call rax // yeni mz nin addressOfEntryPoint i
    xor eax,eax
    jmp protected_crackme.7FF7C3AF4B2B
    mov eax,1
    mov rbx,qword ptr ss:[rsp+2E0]
    add rsp,290
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    ret 
```

Yukarda gördüğünüz kodlar ana binary mizin sonunu içeriyor. Ama merak etmeyin macera daha yeni başlıyor. Önce şifresini çözdüğümüz yeni binary nin bellekteki versiyonunun iz kalmasın diye header kısmının VirtualFree ile salındığını görüyoruz. sonra call rax ile yeni binary mizin addressOfEntryPoint ine doğru bir yolculuğa çıkıyoruz böylece ilk katmanı yani protected_crackme.exe yi bir kenara bırakıyoruz.

## 2. Katman - VM rutini

Yeni exe mizin içine girer girmez ilk fark ettiğimiz şey ağır bir obfuscation. Artık her şeyi anlamlandırmayı bırakıp detaylara odaklanma zamanı geldi.

```
    mov ecx,FFFFFFF6
    call qword ptr ss:[rsp+30] //GetStdHandle
    mov dword ptr ss:[rsp+2C],0
    mov qword ptr ss:[rsp+20],0
    lea r9,qword ptr ss:[rsp+2C]
    mov rcx,rax
    mov rdx,rdi
    mov r8d,10
    call qword ptr ss:[rsp+40] //ReadFile
    mov rcx,rsi
    mov rdx,rdi
    call 140001040 // vm routine
    xor ecx,ecx
    call qword ptr ss:[rsp+48] //ExitProcess
    nop 
    add rsp,60
    pop rbx
    pop rdi
    pop rsi
    ret 
```

yeni exe mizin entry fonksiyonunun son kısımda ana rutin çok net şekilde gözüküyor. İlk olarak GetStdHandle ile STD_INPUT_HANDLE alınıyor. Bu programı çalıştırandan input almak için. Sonra ReadFile ile 16 byte lık bir input isteniyor terminalden. ReadFile ile alınan input vm rutinine aktarılıyor. vm rutini bitince de ne olursa olsun program kapanıyor.

Vm rutini tüm crackme nin olayının döndüğü yer aslında. Burayı anlamak soruyu çözmek anlamına gelecek. Soruya ilk başladığımda bunun bir VM olduğunu anlayana kadar  
Control Flow içinde baya bir debelendiğimi itiraf etmem gerekiyor. VM olduğunu fark edince bir disassembler yazmadan bundan kurtulamayacağımı anladım.

### VM kalbi

```
    mov rdx,qword ptr ds:[rbx+2118]
    cmp rdx,qword ptr ds:[rbx+2110]
    jb 1400083ED
    mov word ptr ds:[rbx+2120],101
    xor al,al
    jmp 14000840A
    mov rax,qword ptr ds:[rbx+2108]
    mov rcx,rbx
    movzx edi,byte ptr ds:[rdx+rax]
    call <next_num>
    xor al,dil
    inc qword ptr ds:[rbx+2118]
    movzx eax,al
    mov rcx,rbx
    mov rdx,qword ptr ds:[rbx+rax*8+2220]
    call rdx
    inc rbp
    cmp rbp,1E8480
    ja 140008431
    cmp byte ptr ds:[rbx+2120],0
    je 1400083D0
```

VM in kalbı burda. [rbx+2118] bizim kaçıncı instruction ı çalıştırdığımızı tutuyor başlangıçta 0. [rbx+2110] ise toplam instruction sayısını tutuyor bu programda 0x26C.
[rbx+2108] de encrypted bytecode larımız var tahmin edeceğiniz üzere tam 0x26C kadar. next_num fonksiyonu önceden ona verilmiş bir anahtar sayesinde rastgele sayı üretiyor argüman olarak [rbx+2118] sayısını alıyor. [rbx+2120] bizim isHalted flag ımız. vm halt opcode larından birini çalıştırınca bu değer 1 oluyor ve vm rutini bitiyor. Koddan da anlayabileceğin gibi eğer toplam instruction sayısını aşarsak da vm bu flag ı set ediyor ve vm rutini gene bitiyor. Bu rutinde nerden geldiğini görmediğiniz ama aslında vm in içine girdiğimizden beri elimizden düşmeyen, fastcall larda kullandığımız this objesini de unutmayalım. bu objenin içinde next_num fonksiyonunu besleyen parametreler, instruction jump table ve daha neler var neler. VM objesi diyebiliriz kısaca.

Rutin şu şekilde işliyor. rbx+2118 ile kaçıncı instruction da olduğumuzu öğreniyoruz sonra toplam instruction sayısını geçtik mi diye kontrol ediyoruz geçtiyse rutin bitiyor geçmediyse rbx+2108 ile bytecode list i alıyoruz bu list den kaçıncı instruction daysak onu çekiyoruz. next_num ile ürettiğimiz sayıyı bunla xor luyoruz böylece decrypted bytecode umuzu elde etmiş oluyoruz.
`0000000140008410 | 48:8B94C3 20220000       | mov rdx,qword ptr ds:[rbx+rax*8+2220]              |`  
bu satırda da hangi bytecode sa o onun fonksiyonunun olduğu yeri buluyoruz sonrada call rdx ile çağrıyoruz.

Ana döngü bu şekilde. ben programın bytecode akışını decrypt etmek için next_num fonksiyonunu inceledim bunu yaparken ve genel olarak programı analiz ederken claude dan çoktan faydalandığımı söylemekten utanacak değilim. next_num fonksiyonunu kullanarak rbx+2108 adresindeki bytecode ların dump unun şifresini çözdüğüm python script ini aşağı bırakıyorum:

``` python
import struct

MASK64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME  = 0x100000001B3


def rol64(x: int, r: int) -> int:
    r &= 63
    if r == 0:
        return x & MASK64
    x &= MASK64
    return ((x << r) | (x >> (64 - r))) & MASK64


def rotr64(x: int, r: int) -> int:
    return rol64(x, 64 - (r & 63))


def fnv1a64(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & MASK64
    return h


def fmix64_variant(h: int) -> int:
    C = 0xFF51AFD7ED558CCD
    h ^= (h >> 0x21)
    h = (h * C) & MASK64
    h ^= (h >> 0x21)
    return h


def round_func(v0, v1, v2, v3, idx, k0, k1, k2, k3, rot):
    c = idx & 0x3F
    r9 = k1 ^ rol64(k2, c)

    rdi = (idx * GOLDEN) & MASK64
    rotacc = (idx * 7) & 0x3F
    rdi = (rdi + k0) & MASK64
    v2 = (v2 + r9) & MASK64
    rdi = (rdi + v0) & MASK64

    r8 = (k3 + idx) & MASK64
    r8 ^= v1

    rax = k0 ^ k3
    rax = rol64(rax, rotacc)
    v3 = v3 ^ rax

    r9 = (rdi + r8) & MASK64

    a0, a1, a2, a3 = rot(idx, 0), rot(idx, 1), rot(idx, 2), rot(idx, 3)

    r8 = rol64(r8, a0)
    v1 = ((r9 ^ r8) + r9) & MASK64

    r9 = rol64(r9, a1)
    v0 = v1 ^ r9

    r8 = (v2 + v3) & MASK64
    v3r = rol64(v3, a2)
    v3 = ((r8 ^ v3r) + r8) & MASK64

    r8b = rol64(r8, a3)
    v2 = v3 ^ r8b

    r8 = (v2 + v1) & MASK64
    v2t = rol64(v2, a1)
    v2 = ((r8 ^ v2t) + r8) & MASK64

    r8c = rol64(r8, a2)
    v1 = v2 ^ r8c

    r8 = (v3 + v0) & MASK64
    v0t = rol64(v0, a3)
    v0 = ((r8 ^ v0t) + r8) & MASK64

    r8d = rol64(r8, a0)
    v3 = v0 ^ r8d

    return v0, v1, v2, v3


def permute_P(state, key_struct_bytes):
    num_rounds = struct.unpack_from("<I", key_struct_bytes, 0)[0]

    def rot(idx, j):
        return key_struct_bytes[4 + idx * 4 + j] & 0x3F

    k0, k1, k2, k3 = struct.unpack_from("<4Q", key_struct_bytes, 0x88)
    v0, v1, v2, v3 = state
    for idx in range(num_rounds):
        v0, v1, v2, v3 = round_func(v0, v1, v2, v3, idx, k0, k1, k2, k3, rot)
    return [v0, v1, v2, v3]


class PRNG:
    """
    this+0x2108 -> data ptr (internal buffer)
    this+0x2110 -> data length
    this+0x2118 -> running index counter (her cagride +1)
    this+0x2128/0x2130/0x2138/0x2140/0x2148 -> k1..k5  (her biri 8 byte, little-endian u64)
    this+0x2150.. -> key_schedule_bytes (4 byte num_rounds + num_rounds*4 byte rot tablosu
                                          + 0x88 offsetine kadar herhangi bir veri (kullanilmiyor)
                                          + 4 adet u64 k0..k3)
    this+0x2200..0x221F -> 32 byte cache
    this+0x21F8 -> son hesaplanan block
    """

    def __init__(self, data: bytes, k1, k2, k3, k4, k5, key_schedule_bytes):
        self.data = data
        self.k1, self.k2, self.k3, self.k4, self.k5 = k1, k2, k3, k4, k5
        self.key_schedule = key_schedule_bytes
        self.cache_block = None
        self.cache_buf = None
        self.counter = 0

    def hash_byte(self, index: int) -> int:
        block = index >> 5
        pos = index & 0x1F

        if block != self.cache_block:
            if block == 0:
                h = 0
            else:
                n = min(block * 32, len(self.data))
                h = fnv1a64(self.data[:n]) if n else FNV_OFFSET
                h = fmix64_variant(h)

            A = h ^ self.k5
            w0 = A ^ self.k1
            w2 = rotr64(A, 0x20) ^ self.k3
            w3 = ((GOLDEN + block) & MASK64) ^ self.k4
            w1 = block ^ self.k2

            state = permute_P([w0, w1, w2, w3], self.key_schedule)

            out = [
                state[0] ^ self.k1,
                state[1] ^ self.k2,
                state[2] ^ self.k3,
                state[3] ^ self.k4,
            ]
            buf = b"".join(v.to_bytes(8, "little") for v in out)

            self.cache_block = block
            self.cache_buf = buf

        return self.cache_buf[pos]

    def process_byte(self, data_byte: int) -> int:
        ks = self.hash_byte(self.counter)
        out = data_byte ^ ks
        self.counter += 1
        return out

    def process_buffer(self, buf: bytes) -> bytes:
        return bytes(self.process_byte(b) for b in buf)


DATA_FILE_PATH = "./internal_data.bin"

K1 = 0x6F31AE3B4C1C5385   # [this+0x2128]
K2 = 0x0C44184CCC0AAA80   # [this+0x2130]
K3 = 0x67155AFF9E337BC7   # [this+0x2138]
K4 = 0x7E0468DD3CEE5F48   # [this+0x2140]
K5 = 0x96C291D366E316C7   # [this+0x2148]

KEY_SCHEDULE_HEX = (
    "10 00 00 00 2A 26 23 14 05 10 05 0C 38 35 34 11 26 25 30 0A 0F 1A 0F 2E 2F 03 35 03 33 1A 03 21 18 0A 0A 17 36 26 17 1B 1A 31 21 1C 06 35 12 2A 03 13 3C 34 38 35 33 31 3A 0C 3A 15 32 33 33 30 34 32 3C 06 0A 20 20 0A 24 1C 3D 32 34 03 39 0F 0A 3A 3C 3B 17 12 1D 32 08 16 1C 39 33 30 13 39 15 25 1B 28 10 2C 13 0F 1D 3A 08 0A 20 3C 0E 20 14 1B 3B 27 22 31 33 04 05 3B 10 14 0B 3D 22 27 35 0C 08 38 00 00 00 00 A7 85 6C FF 13 44 2E 3D D7 EE B9 49 3E AE 43 A0 4D 64 82 89 B5 0E C3 64 EF 67 0A 58 5F 91 A9 1E"
)

if __name__ == "__main__":
    with open(DATA_FILE_PATH, "rb") as f:
        internal_data = f.read()

    assert len(internal_data) == 0x26C, f"beklenen 0x26C bayt, okunan {len(internal_data):#x}"

    key_schedule_bytes = bytes.fromhex(KEY_SCHEDULE_HEX.replace(" ", ""))

    st = PRNG(internal_data, K1, K2, K3, K4, K5, key_schedule_bytes)

    # idx=5 dogrulamasi (beklenen: 0x9c)
    while st.counter < 5:
        st.hash_byte(st.counter)
        st.counter += 1
    keystream_5 = st.hash_byte(5)
    print("hash_byte(5) =", hex(keystream_5), "(beklenen 0x9c)")

    # Ornek: tum buffer'i sirayla isleyip cikan byte dizisini gor
    st2 = PRNG(internal_data, K1, K2, K3, K4, K5, key_schedule_bytes)
    all_states = st2.process_buffer(internal_data)
```

### VM fonksiyonları

Bu VM in toplam 34 adet bytecode u var. instruction jump table dan vm fonksiyonlarını capstone ile çıkarttım:

``` python
# get instruction function from instruction jump table
raw_data = bytes.fromhex("30 64 00 40 01 00 00 00 30 6B 00 40 01 00 00 00...")
addr_list = []
for i in range(0, len(raw_data), 8):
    chunk = raw_data[i:i+8]
    if len(chunk) == 8:
        # 8 byte'lık veriyi int'e çevir (Little Endian)
        addr = int.from_bytes(chunk, byteorder='little')
        addr_list.append(addr)


exe_data = open("crackme_vm.bin", "rb").read() # Exe dosyanızı okuyun
base_addr = 0x140000000 # Exe'nizin ImageBase değeri

from capstone import *

# x64 mimarisi kurulumu
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True 

def parse_functions(binary_data, base_addr, func_addresses):
    func_starts = set(func_addresses)
    
    func_dict = {}
    funcNo_dict = {}

    for funcNo, start_addr in enumerate(func_addresses):
        offset = start_addr - base_addr
        instructions = []
        
        if offset < 0 or offset >= len(binary_data):
            continue

        for insn in md.disasm(binary_data[offset-0xc00:], start_addr):

            if insn.bytes[0] == 0x90 or insn.bytes[0] == 0xCC:
                break
            
            if insn.address in func_starts and insn.address != start_addr:
                break
            
            instructions.append(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
        
        if func_dict.get(start_addr) != None:
            continue
        func_dict[start_addr] = True
        funcNo_dict[funcNo] = instructions

    return funcNo_dict



funcNo_dict = parse_functions(exe_data, base_addr, addr_list)

for k in funcNo_dict.keys():
    func = funcNo_dict[k]
    f = open(f"all_funcs/func{k}.txt", "w")
    f.write(str(func))
    f.close()

```

Her VM fonksiyonu birbirine benziyor ayırt edilmeleri çok kolay.  
Örnek olarak Mov Opcode unu inceleyelim:

```
0x140006280: mov qword ptr [rsp + 8], rbx
0x140006285: mov qword ptr [rsp + 0x10], rsi
0x14000628a: push rdi
0x14000628b: sub rsp, 0x20
0x14000628f: mov rdx, qword ptr [rcx + 0x2118]
0x140006296: mov rdi, rcx
0x140006299: cmp rdx, qword ptr [rcx + 0x2110]
0x1400062a0: jb 0x1400062b0
0x1400062a2: mov word ptr [rcx + 0x2120], 0x101
0x1400062ab: xor sil, sil
0x1400062ae: jmp 0x1400062d4
0x1400062b0: mov rax, qword ptr [rcx + 0x2108]
0x1400062b7: movzx ebx, byte ptr [rdx + rax]
0x1400062bb: call next_num
0x1400062c0: movzx esi, al
0x1400062c3: xor sil, bl
0x1400062c6: inc qword ptr [rdi + 0x2118]
0x1400062cd: mov rdx, qword ptr [rdi + 0x2118]
0x1400062d4: and sil, 0x1f
0x1400062d8: cmp rdx, qword ptr [rdi + 0x2110]
0x1400062df: jb 0x1400062ee
0x1400062e1: mov word ptr [rdi + 0x2120], 0x101
0x1400062ea: xor al, al
0x1400062ec: jmp 0x14000630a
0x1400062ee: mov rax, qword ptr [rdi + 0x2108]
0x1400062f5: mov rcx, rdi
0x1400062f8: movzx ebx, byte ptr [rdx + rax]
0x1400062fc: call next_num
0x140006301: xor al, bl
0x140006303: inc qword ptr [rdi + 0x2118]
0x14000630a: mov rbx, qword ptr [rsp + 0x30]
0x14000630f: and eax, 0x1f
0x140006312: movzx ecx, sil
0x140006316: mov rsi, qword ptr [rsp + 0x38]
0x14000631b: mov rax, qword ptr [rdi + rax*8]
0x14000631f: mov qword ptr [rdi + rcx*8], rax
0x140006323: add rsp, 0x20
0x140006327: pop rdi
0x140006328: ret 
```

Her opcode fonksiyonu şu iki ana bölgeden oluşuyor: get arguments + do job

next_num fonksiyonunu bu opcode fonksiyonlarının içinde de görüyoruz burdaki ama argüman ları elde etmek. bytecode list imizde sadece instruction opcode lar yok onların argümanları da var. VM kalbi dediğim yerde bytecode list den alıp decrypt ettiğimiz bytecode u jump için kullanırken burda argüman olarak kullanıyoruz. move opcode fonksiyonunun iki kere next_num u çağırdığını fark etmişsinizdir. aynı şekilde o anki şifreli bytecode umuz ile xor lanıp doğru bytecode elde ediltikten sonra bunlara yapılan farklı bir muamele dikkatinizi çekecektir  
`and sil, 0x1f` 0x1f en düşük 5 bit i alıp gerisini truncate ediyor. bunu yapma sebebi mov opcode unun adreslerle değil register larla çalışması. vm in 32 adet register ı var bu yüzden range imiz 5 bit.

move opcode unda ilk argümanımız destination sonraki ise source. `mov dst, src`. peki bu aktarım nerde? fonksiyonun sonuna bakalım:
```
0x14000631b: mov rax, qword ptr [rdi + rax*8]
0x14000631f: mov qword ptr [rdi + rcx*8], rax
```

işte tam burda. bir register ın tekabul ettiği adresteki 8 byte diğerininkine koyuluyor. Move işlemi!  
tüm next_num çağrılarından sonra yapılan
`inc qword ptr [rdi + 0x2118]` hareketini dikkatlerinize sunmak isterim bu aslında gayet mantıklı size [rbx+2118] in kaçınc instruction da olduğumuzun sayısını tuttuğunu söylemiştim aslında yaptığı şey bytecode list de kaçıncı bytecode da olduğumuzu tutmak. argümanlarda bytecode list de olduğu için onları arkada bırakabilmek içinde +1 ekliyor.

Şimdi biraz daha farklı bir işlem yapan LOAD_IMM64 opcode unun fonksiyonunu inceleyelim:

```
0x1400060c0: mov qword ptr [rsp + 0x10], rsi
0x1400060c5: push rdi
0x1400060c6: sub rsp, 0x20
0x1400060ca: mov rdx, qword ptr [rcx + 0x2118]
0x1400060d1: mov rdi, rcx
0x1400060d4: cmp rdx, qword ptr [rcx + 0x2110]
0x1400060db: jb 0x1400060eb
0x1400060dd: mov word ptr [rcx + 0x2120], 0x101
0x1400060e6: xor sil, sil
0x1400060e9: jmp 0x140006112
0x1400060eb: mov rax, qword ptr [rcx + 0x2108]
0x1400060f2: mov qword ptr [rsp + 0x30], rbx
0x1400060f7: movzx ebx, byte ptr [rdx + rax]
0x1400060fb: call 0x1400075c0
0x140006100: movzx esi, al
0x140006103: xor sil, bl
0x140006106: mov rbx, qword ptr [rsp + 0x30]
0x14000610b: inc qword ptr [rdi + 0x2118]
0x140006112: mov rcx, rdi
0x140006115: call 0x140005630
0x14000611a: and esi, 0x1f
0x14000611d: mov qword ptr [rdi + rsi*8], rax
0x140006121: mov rsi, qword ptr [rsp + 0x38]
0x140006126: add rsp, 0x20
0x14000612a: pop rdi
0x14000612b: ret 
```

Daha kısa olması bir yana burda bir de 0x140005630 adresinin çağrıldığını görüyoruz. Nedir bu? Aslında bir helper fonksiyon. yaptığı şey 8 kere next_num çağırmak ve onları shift leyip birleştirerek opcode un adından da anlaşılacağı gibi bir 64bitlik sabit i hedef register ın adresine yerleştirmek. Pekala bu sabit bytecode içinde olduğu için onu ordan çıkarmak amacıyla 8 kere next_num çağırıyor. Her next_num un bytecode list den sadece bir byte çıkardığını hatırlayın.


Opcode fonksiyonlarının yeterince anlaşıldığını düşünüyorum ancak inceleyeceğimiz vm programında anlaşılmasının bizim için çok önemli olacağını düşündüğüm bir opcode daha var. 0. opcode, diğer bir adıyla NATIVE_CALL

```
0x140006430: mov qword ptr [rsp + 0x10], rbx
0x140006435: mov qword ptr [rsp + 0x18], rsi
0x14000643a: mov qword ptr [rsp + 0x20], rdi
0x14000643f: push r14
0x140006441: sub rsp, 0x60
0x140006445: mov rdx, qword ptr [rcx + 0x2118]
0x14000644c: mov rbx, rcx
0x14000644f: cmp rdx, qword ptr [rcx + 0x2110]
0x140006456: jb 0x140006466
0x140006458: mov word ptr [rcx + 0x2120], 0x101
0x140006461: xor sil, sil
0x140006464: jmp 0x14000648a
0x140006466: mov rax, qword ptr [rcx + 0x2108]
0x14000646d: movzx edi, byte ptr [rdx + rax]
0x140006471: call 0x1400075c0
0x140006476: movzx esi, al
0x140006479: xor sil, dil
0x14000647c: inc qword ptr [rbx + 0x2118]
0x140006483: mov rdx, qword ptr [rbx + 0x2118]
0x14000648a: cmp rdx, qword ptr [rbx + 0x2110]
0x140006491: jb 0x1400064a0
0x140006493: mov word ptr [rbx + 0x2120], 0x101
0x14000649c: xor cl, cl
0x14000649e: jmp 0x1400064c0
0x1400064a0: mov rax, qword ptr [rbx + 0x2108]
0x1400064a7: mov rcx, rbx
0x1400064aa: movzx edi, byte ptr [rdx + rax]
0x1400064ae: call 0x1400075c0
0x1400064b3: movzx ecx, al
0x1400064b6: xor cl, dil
0x1400064b9: inc qword ptr [rbx + 0x2118]
0x1400064c0: mov r14, qword ptr [rbx + 0x2a38]
0x1400064c7: mov qword ptr [rsp + 0x70], rbp
0x1400064cc: test r14, r14
0x1400064cf: je 0x140006594
0x1400064d5: movzx ebp, sil
0x1400064d9: cmp rbp, qword ptr [rbx + 0x2a40]
0x1400064e0: jae 0x140006594
0x1400064e6: mov edx, 6
0x1400064eb: movzx eax, cl
0x1400064ee: cmp cl, dl
0x1400064f0: cmova eax, edx
0x1400064f3: mov edx, dword ptr [rbx + 0x2100]
0x1400064f9: movzx r8d, al
0x1400064fd: cmp edx, r8d
0x140006500: jb 0x140006594
0x140006506: xor ecx, ecx
0x140006508: sub r8, 1
0x14000650c: mov qword ptr [rsp + 0x30], rcx
0x140006511: mov r10d, ecx
0x140006514: mov qword ptr [rsp + 0x38], rcx
0x140006519: mov r11d, ecx
0x14000651c: mov qword ptr [rsp + 0x40], rcx
0x140006521: mov r9d, ecx
0x140006524: mov qword ptr [rsp + 0x48], rcx
0x140006529: mov edi, ecx
0x14000652b: mov qword ptr [rsp + 0x50], rcx
0x140006530: mov esi, ecx
0x140006532: mov qword ptr [rsp + 0x58], rcx
0x140006537: js 0x140006579
0x140006539: nop dword ptr [rax]
0x140006540: dec edx
0x140006542: mov dword ptr [rbx + 0x2100], edx
0x140006548: mov rcx, qword ptr [rbx + rdx*8 + 0x100]
0x140006550: mov qword ptr [rsp + r8*8 + 0x30], rcx
0x140006555: sub r8, 1
0x140006559: jns 0x140006540
0x14000655b: mov rsi, qword ptr [rsp + 0x58]
0x140006560: mov rdi, qword ptr [rsp + 0x50]
0x140006565: mov r9, qword ptr [rsp + 0x48]
0x14000656a: mov r11, qword ptr [rsp + 0x40]
0x14000656f: mov r10, qword ptr [rsp + 0x38]
0x140006574: mov rcx, qword ptr [rsp + 0x30]
0x140006579: mov rax, qword ptr [r14 + rbp*8]
0x14000657d: mov r8, r11
0x140006580: mov qword ptr [rsp + 0x28], rsi
0x140006585: mov rdx, r10
0x140006588: mov qword ptr [rsp + 0x20], rdi
0x14000658d: call rax
0x14000658f: mov qword ptr [rbx], rax
0x140006592: jmp 0x14000659d
0x140006594: mov word ptr [rbx + 0x2120], 0x101
0x14000659d: mov rbp, qword ptr [rsp + 0x70]
0x1400065a2: lea r11, [rsp + 0x60]
0x1400065a7: mov rbx, qword ptr [r11 + 0x18]
0x1400065ab: mov rsi, qword ptr [r11 + 0x20]
0x1400065af: mov rdi, qword ptr [r11 + 0x28]
0x1400065b3: mov rsp, r11
0x1400065b6: pop r14
0x1400065b8: ret 
```

Bu opcode 2 adet argüman alıyor. ilki hangi native fonksiyonu çağıracağına karar vermesini sağlayan bir index ikincisi ise bu fonksiyona kaç tane argüman gönderileceğini söyleyen arity number. NATIVE_CALL opcode u çağrılmadan önce bir argümanımız varsa onuda PUSH(0x11) opcode u ile gönderiyoruz. Push opcode u bir register numarasını stack e ekliyor. NATIVE_CALL 0 dan farklı bir argüman sayısı ile çağrılırsa da stack deki bu değerleri aynı sıra ile parametre olarak kullanıyor. NATIVE_CALL opcode u çalıştırıldığında çıktısını reg0 a koyuyor 0 numaralı register bu opcode için return değerini tutuyor yani.

Bu programın native function table ındaki fonksiyonlar 6 adet. İncelediğimiz program bunlardan sadece 3 tanesini çağırıyor. Fonksiyonlar ağır obfuscate edildiği için sadece kullanılanları analiz etmeye efor sarf ettim, kusura bakmayın. Şimdi analiz ettiklerimin işlevlerini açıklıyım.  
- native_call(0, 0): hiçbir argüman almıyor yaptığı şey peb struct daki beingDebugged ve NtGlobalFlag field lerindeki değerleri or layıp birleştiriyor. Ve dönüş değeri bu oluyor. eğer debugger varsa dönüş değeri (beingDebugged or NtGlobalFlag) varyantları,  eğer yoksa 0 oluyor.
- native_call(1, x): bir çeşit crc32 fonksiyonu çağrılıyor. Binary nin .linti section u var. bu section şuan incelediğimiz kodda hiç kullanılmıyor ama nedense var. ve bu fonksiyon onun crc32 hash ini alıyor gibi gözüküyor. programda çağrılıyor ama argüman sayısı olarak 0 veriliyor. Sıfır verildiği içinde crc32 işlemi yapılmıyor. Açıkçası tam olarak ne amaçla ve nasıl çalıştığını anlayamadım.
- native_call(3, 3): memcpy implementasyonu, argümanların anlamı sırayla dst, src, count
- native_call(4, 3): feistel algoritması implementasyonu, argüman sırasına göre ilk 8 byte pointer, son 8 byte pointer, ve 16*8 byte pointer, açıklama yetersiz evet ama programda nasıl kullanıldığını açıklayınca anlamlı olacak
- native_call(2, 4): splitmax64 implementasyonu, argüman sırasına göre input pointer, native_call(0, 0), native_call(1, x), output pointer

argümanlar yukarda anlattığım gibi PUSH opcode u ile doldurulduğu için her şey olabilir ama ben size programda dolduruldukları şekilde anlattım.

### VM Disassmbly

artık opcode ları anlamayı öğrendiğimize göre dilerseniz size bu vm için hazırladığım disassembly kodunu paylaşayım:

``` python
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Instruction:
    addr: int
    opcode: int
    mnemonic: str
    operands: List[int] = field(default_factory=list)
    raw_len: int = 1

    def __repr__(self):
        types = OPERAND_TYPES.get(self.opcode, [])
        parts = []
        for o, t in zip(self.operands, types):
            if t == "reg":
                parts.append(f"r{o}")
            elif t == "byte":
                parts.append(f"#{o}")
            else:
                parts.append(hex(o) if o >= 0 else str(o))
        return f"0x{self.addr:04x}: {self.mnemonic:<14} {', '.join(parts)}"


OPERAND_TYPES = {
    0:  ["byte", "byte"],          # NATIVE_CALL(func_idx, arg_count)
    1:  ["reg", "reg", "reg"],     # UMOD(dest, dividend, divisor)        unsigned
    2:  ["reg", "reg", "reg"],     # AND(dest, src1, src2)
    3:  ["reg", "reg"],            # NOT(dest, src)
    4:  ["reg", "reg", "reg"],     # SUB(dest, src1, src2)
    5:  ["reg", "reg", "reg"],     # SHR(dest, src, count_reg)            logical
    6:  ["reg", "byte"],           # LOAD_CONST(dest, const_idx)
    7:  ["reg", "imm64"],          # LOAD_IMM64(dest, imm64) -> REG[dest] = imm64
    8:  ["reg", "reg", "reg"],     # CMP_EQ(dest, src1, src2)
    9:  ["reg", "reg", "reg"],     # SDIV(dest, dividend, divisor)        signed quotient
    10: ["reg", "reg", "reg"],     # OR(dest, src1, src2)
    11: ["reg", "imm32"],          # LOAD_PTR(dest, rva)
    12: [],                         # HALT (explicit, status=1)
    13: ["imm16"],                  # JMP(rel_offset)
    14: ["reg", "reg", "reg"],     # SMOD(dest, dividend, divisor)        signed remainder
    15: ["reg", "imm16"],          # JZ(cond_reg, rel_offset)
    16: ["byte"],                   # STACK_ALU(op_sel)  0..5=add/sub/imul/xor/and/or
    17: ["reg"],                    # PUSH(src)
    18: ["reg", "reg", "reg"],     # UDIV(dest, dividend, divisor)        unsigned quotient
    19: ["reg", "reg", "reg"],     # ROL(dest, src, count_reg)
    20: ["reg", "reg", "reg"],     # IMUL(dest, src1, src2)
    21: ["reg", "reg", "reg"],     # XOR(dest, src1, src2)
    22: ["reg", "reg", "reg"],     # SAR(dest, src, count_reg)            arithmetic
    23: ["reg", "reg", "byte"],    # MEM_LOAD(dest, addr_reg, size)       size in {1,2,4,8}
    24: ["reg"],                    # POP(dest)
    25: ["reg", "reg", "reg"],     # CMP_ULT(dest, src1, src2)            unsigned <
    26: ["reg", "reg"],             # MOV(dest, src)
    27: ["reg", "reg", "byte"],    # MEM_STORE(addr_reg, value_reg, size)
    28: ["reg", "reg", "reg"],     # ADD(dest, src1, src2)
    29: ["reg", "imm16"],          # JNZ(cond_reg, rel_offset)
    30: ["reg", "reg", "reg"],     # SHL(dest, src, count_reg)
    31: ["byte"],                   # INVOKE_TABLE2(idx)  [ACIK SORU - tail-jump table2]
    32: ["reg", "byte"],           # CALL_INDIRECT(func_ptr_reg, arg_count)
    # 33 ve sonrasi: bilinmeyen/trap (jump table default handler)
}

MNEMONICS = {
    0:  "NATIVE_CALL",
    1:  "UMOD",
    2:  "AND",
    3:  "NOT",
    4:  "SUB",
    5:  "SHR",
    6:  "LOAD_CONST",
    7:  "LOAD_IMM64",
    8:  "CMP_EQ",
    9:  "SDIV",
    10: "OR",
    11: "LOAD_PTR",
    12: "HALT",
    13: "JMP",
    14: "SMOD",
    15: "JZ",
    16: "STACK_ALU",
    17: "PUSH",
    18: "UDIV",
    19: "ROL",
    20: "IMUL",
    21: "XOR",
    22: "SAR",
    23: "MEM_LOAD",
    24: "POP",
    25: "CMP_ULT",
    26: "MOV",
    27: "MEM_STORE",
    28: "ADD",
    29: "JNZ",
    30: "SHL",
    31: "INVOKE_TABLE2",
    32: "CALL_INDIRECT",
}

# STACK_ALU (opcode 16) op-selector tablosu (0..5), >=6 ise sonuc 0
STACK_ALU_OPS = {0: "add", 1: "sub", 2: "imul", 3: "xor", 4: "and", 5: "or"}

# MEM_LOAD/MEM_STORE (opcode 23/27) size-selector -> byte genisligi
# (1=byte, 2=word, 4=dword, baska herhangi bir deger=qword fallback)
MEM_SIZE_MAP = {1: 1, 2: 2, 4: 4}  # eslesmeyen her deger qword(8) sayilir


class VMDisassembler:
    def __init__(self, bytecode: List[int]):
        self.bc = bytecode
        self.ip = 0
        self.instructions: List[Instruction] = []
        self.unknown_opcodes = set()

    def _read_byte(self) -> int:
        b = self.bc[self.ip]
        self.ip += 1
        return b

    def _read_imm16(self) -> int:
        b0 = self._read_byte()
        b1 = self._read_byte()
        val = (b1 << 8) | b0
        if val & 0x8000:
            val -= 0x10000
        return val

    def _read_imm32(self) -> int:
        b0 = self._read_byte()
        b1 = self._read_byte()
        b2 = self._read_byte()
        b3 = self._read_byte()
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

    def _read_imm64(self) -> int:
        """sub_140005630: 8 byte, little-endian birlesim -> 64-bit literal."""
        val = 0
        for i in range(8):
            val |= self._read_byte() << (8 * i)
        return val

    def disassemble(self, max_instructions: Optional[int] = None) -> List[Instruction]:
        self.ip = 0
        self.instructions = []
        while self.ip < len(self.bc):
            if max_instructions is not None and len(self.instructions) >= max_instructions:
                break

            start_ip = self.ip
            opcode = self._read_byte()

            if opcode not in OPERAND_TYPES:
                self.unknown_opcodes.add(opcode)
                instr = Instruction(
                    addr=start_ip, opcode=opcode,
                    mnemonic=f"UNK_{opcode:#x}/TRAP",
                    operands=[], raw_len=self.ip - start_ip,
                )
                self.instructions.append(instr)
                break  # bilinmeyen opcode -> stream'i yanlis hizalamamak icin dur

            operand_types = OPERAND_TYPES[opcode]
            operands = []
            for t in operand_types:
                if t == "reg":
                    operands.append(self._read_byte() & 0x1F)
                elif t == "byte":
                    operands.append(self._read_byte())
                elif t == "imm16":
                    operands.append(self._read_imm16())
                elif t == "imm32":
                    operands.append(self._read_imm32())
                elif t == "imm64":
                    operands.append(self._read_imm64())
                else:
                    raise ValueError(f"bilinmeyen operand tipi: {t}")

            instr = Instruction(
                addr=start_ip, opcode=opcode,
                mnemonic=MNEMONICS.get(opcode, f"OP_{opcode}"),
                operands=operands, raw_len=self.ip - start_ip,
            )
            self.instructions.append(instr)

        return self.instructions

    def pretty_print(self):
        for instr in self.instructions:
            extra = ""
            if instr.mnemonic == "STACK_ALU" and instr.operands:
                extra = f"  ; {STACK_ALU_OPS.get(instr.operands[0], 'invalid->0')}"
            elif instr.mnemonic in ("MEM_LOAD", "MEM_STORE") and len(instr.operands) >= 3:
                sz = MEM_SIZE_MAP.get(instr.operands[2], 8)
                extra = f"  ; size={sz} byte"
            print(repr(instr) + extra)
        if self.unknown_opcodes:
            print()
            print(f"Bilinmeyen opcode'lar: {sorted(hex(o) for o in self.unknown_opcodes)}")


if __name__ == "__main__":
    f = open("bytecodes.bin", "rb")
    bytecodes = f.read()
    vm = VMDisassembler(bytecodes)
    vm.disassemble()
    vm.pretty_print()
```

'bytecodes.bin' size yukarda verdiğim PRNG kodu ile çözülen şifreli bytecode ların şifresiz hali.
Bu kodu çalıştırınca VM in ne yaptığı tüm çıplaklığı ile görünebilir hale geliyor.

```
0x0000: ROL            r30, r31, r30
0x0004: SUB            r30, r31, r30
0x0008: OR             r31, r30, r30
0x000c: LOAD_PTR       r3, 0x0
0x0012: ROL            r31, r30, r30
0x0016: NOT            r31, r30
0x0019: LOAD_PTR       r4, 0x80
0x001f: CMP_EQ         r30, r30, r31
0x0023: OR             r30, r30, r31
0x0027: LOAD_PTR       r5, 0xa0
0x002d: SHR            r31, r31, r30
0x0031: ADD            r31, r30, r31
0x0035: LOAD_PTR       r6, 0xa8
0x003b: SHL            r30, r31, r31
0x003f: LOAD_PTR       r7, 0xb0
0x0045: NATIVE_CALL    #0, #0
0x0048: MOV            r8, r0
0x004b: NATIVE_CALL    #1, #0
0x004e: MOV            r9, r0
0x0051: LOAD_IMM64     r31, 0xffffffff
0x005b: AND            r9, r9, r31
0x005f: CMP_ULT        r30, r30, r31
0x0063: AND            r30, r30, r31
0x0067: PUSH           r2
0x0069: PUSH           r8
0x006b: PUSH           r9
0x006d: PUSH           r3
0x006f: NATIVE_CALL    #2, #4
0x0072: LOAD_IMM64     r31, 0x0
0x007c: PUSH           r31
0x007e: POP            r15
0x0080: JMP            0xb2
0x0083: MEM_LOAD       r10, r1, #8  ; size=8 byte
0x0087: XOR            r30, r31, r30
0x008b: CMP_ULT        r31, r31, r30
0x008f: LOAD_IMM64     r31, 0xfffffff5 // STD_OUTPUT_HANDLE
0x0099: PUSH           r31
0x009b: CALL_INDIRECT  r10, #1 // GetStdHandle
0x009e: MOV            r11, r0
0x00a1: IMUL           r31, r31, r31
0x00a5: SHR            r31, r31, r30
0x00a9: SHL            r30, r31, r30
0x00ad: LOAD_IMM64     r30, 0x0
0x00b7: MEM_STORE      r7, r30, #4  ; size=4 byte
0x00bb: MOV            r12, r1
0x00be: LOAD_IMM64     r30, 0x8
0x00c8: ADD            r12, r12, r30
0x00cc: MEM_LOAD       r13, r12, #8  ; size=8 byte
0x00d0: ROL            r30, r30, r30
0x00d4: IMUL           r30, r31, r31
0x00d8: OR             r31, r31, r30
0x00dc: PUSH           r11
0x00de: PUSH           r4
0x00e0: LOAD_IMM64     r31, 0x20
0x00ea: PUSH           r31
0x00ec: PUSH           r7
0x00ee: LOAD_IMM64     r31, 0x0
0x00f8: PUSH           r31
0x00fa: CALL_INDIRECT  r13, #5 // WriteFile
0x00fd: MOV            r14, r0
0x0100: LOAD_IMM64     r31, 0xffffffff
0x010a: AND            r14, r14, r31
0x010e: AND            r31, r31, r31
0x0112: ADD            r31, r30, r30
0x0116: IMUL           r30, r30, r31
0x011a: AND            r30, r30, r31
0x011e: AND            r30, r30, r31
0x0122: CMP_EQ         r31, r30, r31
0x0126: ADD            r31, r31, r30
0x012a: LOAD_IMM64     r31, 0x79c2a59e4d609360
0x0134: HALT           
0x0135: XOR            r30, r30, r31
0x0139: SHR            r30, r31, r30
0x013d: SUB            r30, r31, r30
0x0141: LOAD_CONST     r31, #0
0x0144: MOV            r16, r31
0x0147: LOAD_IMM64     r31, 0x1
0x0151: IMUL           r31, r15, r31
0x0155: ADD            r16, r16, r31
0x0159: SUB            r31, r30, r30
0x015d: PUSH           r5
0x015f: PUSH           r16
0x0161: LOAD_IMM64     r31, 0x8
0x016b: PUSH           r31
0x016d: NATIVE_CALL    #3, #3
0x0170: MOV            r17, r0
0x0173: IMUL           r31, r30, r31
0x0177: CMP_EQ         r30, r31, r30
0x017b: CMP_EQ         r31, r30, r31
0x017f: MOV            r18, r16
0x0182: LOAD_IMM64     r30, 0x8
0x018c: ADD            r18, r18, r30
0x0190: ROL            r30, r31, r30
0x0194: PUSH           r6
0x0196: PUSH           r18
0x0198: LOAD_IMM64     r31, 0x8
0x01a2: PUSH           r31
0x01a4: NATIVE_CALL    #3, #3
0x01a7: MOV            r19, r0
0x01aa: SUB            r31, r31, r31
0x01ae: PUSH           r5
0x01b0: PUSH           r6
0x01b2: PUSH           r3
0x01b4: NATIVE_CALL    #4, #3
0x01b7: CMP_ULT        r30, r31, r31
0x01bb: CMP_EQ         r31, r31, r30
0x01bf: MOV            r20, r4
0x01c2: LOAD_IMM64     r31, 0x1
0x01cc: IMUL           r31, r15, r31
0x01d0: ADD            r20, r20, r31
0x01d4: CMP_ULT        r31, r30, r31
0x01d8: OR             r30, r30, r30
0x01dc: AND            r30, r31, r30
0x01e0: PUSH           r20
0x01e2: PUSH           r5
0x01e4: LOAD_IMM64     r31, 0x8
0x01ee: PUSH           r31
0x01f0: NATIVE_CALL    #3, #3
0x01f3: MOV            r21, r0
0x01f6: NOT            r31, r31
0x01f9: ROL            r31, r30, r31
0x01fd: MOV            r22, r20
0x0200: LOAD_IMM64     r30, 0x8
0x020a: ADD            r22, r22, r30
0x020e: MOV            r31, r31
0x0211: ADD            r30, r30, r30
0x0215: PUSH           r22
0x0217: PUSH           r6
0x0219: LOAD_IMM64     r31, 0x8
0x0223: PUSH           r31
0x0225: NATIVE_CALL    #3, #3
0x0228: MOV            r23, r0
0x022b: CMP_EQ         r30, r30, r30
0x022f: ADD            r31, r30, r30
0x0233: ROL            r31, r31, r30
0x0237: NOT            r30, r30
0x023a: AND            r30, r30, r30
0x023e: LOAD_IMM64     r30, 0x10
0x0248: ADD            r24, r15, r30
0x024c: LOAD_IMM64     r30, 0x0
0x0256: CMP_EQ         r25, r15, r30
0x025a: SHR            r30, r31, r31
0x025e: JZ             r25, 0x7
0x0262: PUSH           r24
0x0264: POP            r15
0x0266: JMP            -308
0x0269: JMP            -489
```

Bu kodun yaptığı şey özetle:  

native_call(0, 0) ile debugger flag ı hazırla  

native_call(2, 4) ile input u splitmax64 algoritmasından geçir ve 16*8 byte lık bir output hazırla. Eğer debugger checker bizi fark etmişse bu output 0x7001 varyantları da algoritmaya dahil olduğu için bozuluyor böylece doğru input u girmiş olsa dahi debugger açık olduğu için yanlış splitmax output u çıkarıyoruz.  

REF_DATA adında 32 byte lık VM object in içindeki sabit bir değer kullanılarak native_call(4, 3) ile iki turda önce REF_DATA nın ilk 16 byte ını sonrada son 16 byte ını splitmax çıktımız ile feistel algoritmasından geçiriyoruz. Değişen 32 byte ı da WriteFile ile stdOut a yani terminal e yazıyoruz.

Programın yaptığı şey bundan ibaret. Yani doğru girdiyi bulmamıza imkan sağlayacak şekilde tasarlanmış bir crackme değil. Bu beni gerçekten üzdü çünkü çok emek verip doğru output u alamadım. Doğru output u almanın tek yolu splitmax ve feistel algoritmalarını REF_DATA ya göre tersine çevirerek brute force lamak. Ama bu mantıklı bir süreye göre ayarlanmamış. denemelerimde girdinin 7 byte olmadığını öğrendim. 8 ve daha sonrası içinse yıllarımı harcamam lazım. Pratik olarak mantıklı değil o yüzden doğru girdiyi aramayı bıraktım. Crackme yi çözme şansı verilerek hazırlamamışlar.

Neyse aşağıda crackme ile birebir aynı girdi ye çıktı veren python kodunu bırakayım:

``` python
MASK64 = 0xFFFFFFFFFFFFFFFF
GOLDEN = 0x9E3779B97F4A7C15
C1 = 0xBF58476D1CE4E5B9
C2 = 0x94D049BB133111EB

REF_DATA = bytes.fromhex(
    "1BA3FB429A2E77A880A8673B3932A8DD"
    "427E6A2782D4026B61B9E6D2575AFA56"
)

ANTIDEBUG_FLAG_NORMAL = 0x0      # debugger yokken (normal calistirma)
ANTIDEBUG_FLAG_DEBUGGER = 0x7001  # debugger varken (sadece bilgi icin)


def u64(x: int) -> int:
    return x & MASK64


def rol64(x: int, n: int) -> int:
    n &= 63
    x &= MASK64
    if n == 0:
        return x
    return ((x << n) | (x >> (64 - n))) & MASK64


def fold_le64(data8: bytes) -> int:
    val = 0
    for i, b in enumerate(data8):
        val |= b << (i * 8)
    return val


def unfold_le64(val: int) -> bytes:
    return val.to_bytes(8, "little")


def splitmix64_step(state: int):
    state = u64(state + GOLDEN)
    z = state
    z = u64((z >> 30) ^ z)
    z = u64(z * C1)
    z = u64((z >> 27) ^ z)
    z = u64(z * C2)
    out = u64(z ^ (z >> 31))
    return state, out


def feistel_mix(r9: int, r15: int) -> int:
    rsi = rol64(r9, 0x11)
    rsi = u64(rsi + GOLDEN)
    tmp = r15 ^ rsi
    rsi = rol64(rsi, 0x21)
    rsi ^= tmp
    return rsi


def compute_seed(input_bytes: bytes, antidebug_flag: int) -> int:
    rbp = fold_le64(input_bytes[0:8])
    rbx = fold_le64(input_bytes[8:16])

    seed = rol64(rbx, 32)
    seed ^= 0xA5A5A5A5A5A5A5A5
    seed = u64(seed + rbp)
    seed ^= antidebug_flag
    return seed


def compute_hash_array(input_bytes: bytes, antidebug_flag: int) -> list:
    state = compute_seed(input_bytes, antidebug_flag)
    out = []
    for _ in range(16):
        state, h = splitmix64_step(state)
        out.append(h)
    return out


def feistel_half(hash_arr: list, ref_half: bytes) -> bytes:
    rcx = fold_le64(ref_half[0:8])
    r15 = fold_le64(ref_half[8:16])
    for i in range(15, -1, -1):
        r9 = hash_arr[i] ^ rcx
        new_rcx = feistel_mix(r9, r15)
        r15 = rcx
        rcx = new_rcx
    return unfold_le64(rcx) + unfold_le64(r15)


def run_program(input_bytes: bytes, antidebug_flag: int = ANTIDEBUG_FLAG_NORMAL) -> bytes:
    if len(input_bytes) <= 14:
        padded = input_bytes + b"\r\n" + b"\x00" * (14 - len(input_bytes))
    elif len(input_bytes) == 15:
        # \r\n icin yer yok, sadece \r sigar, kalan pad
        padded = input_bytes + b"\r"
    else:
        padded = input_bytes[:16]

    input_bytes = padded[:16]

    hash_arr = compute_hash_array(input_bytes, antidebug_flag)
    out0 = feistel_half(hash_arr, REF_DATA[0:16])
    out1 = feistel_half(hash_arr, REF_DATA[16:32])
    return out0 + out1



input_bytes = ("qwertyuopasdfghj").encode()
antidebug = ANTIDEBUG_FLAG_NORMAL # ANTIDEBUG_FLAG_DEBUGGER

original_len = len(input_bytes)
if original_len <= 14:
    padded_bytes = input_bytes + b"\r\n" + b"\x00" * (14 - original_len)
elif original_len == 15:
    padded_bytes = input_bytes + b"\r"
elif original_len == 16:
    padded_bytes = input_bytes
else:
    padded_bytes = input_bytes[:16]

output = run_program(input_bytes, antidebug)

print(f"Girdi (orijinal, {original_len} byte) : {input_bytes!r}")
print(f"Girdi (islenen, 16 byte)        : {padded_bytes!r}")
print(f"Girdi (islenen, hex)            : {padded_bytes.hex()}")
print(f"antidebug_flag                  : {hex(antidebug)}")
print()
print(f"Cikti (32 byte) : {output!r}")
print(f"Cikti (hex)     : {output.hex()}")
print()
print("--- RAW CIKTI byte-by-byte (yazdirilamayan karakterler '.' olarak gosterildi) ---")
readable = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in output)
print(readable)
```

Umarım keyif almışsınızdır. Selametle!