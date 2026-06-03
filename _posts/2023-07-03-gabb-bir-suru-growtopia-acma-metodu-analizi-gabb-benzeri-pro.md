---
layout: post
title: "GABB bir sürü Growtopia açma metodu analizi | GABB benzeri program yazma | Mutex Protection Bypass"
date: 2023-07-03
source: "https://www.turkhackteam.org/konular/gabb-bir-suru-growtopia-acma-metodu-analizi-gabb-benzeri-program-yazma-mutex-protection-bypass.2042549/"
---

Selam arkadaşlar geçen günlerde forumda açılan şu konuyu gördüm:  
[https://www.turkhackteam.org/konular/coklu-sayfa-acma.2042259/](https://www.turkhackteam.org/konular/coklu-sayfa-acma.2042259/)  
  
Konuda yapılmak istenen şey growtopia adlı oyunu birden fazla defa açıcak bir program arayışıydı bilenler bilir bunun için kullanılan hali hazırda çalışan GABB adlı bir program var bu program aracılığıyla birden fazla kez growtopia oyununu açıp her birinde giriş yapıp bot hesaplarınızla spam tarzı şeyler yapabiliyorsunuz.  
  
Bende bu işin arka planını araştırmak istedim. Tersine Mühendis kimliğim ile bu konuya bir bakış atmak ve arka planda neler döndüğünü anlamak, analiz etmek istedim. İsterseniz maceraya başlayalım.  
  
Yapmak istediğim şey üst üste birden fazla oyun açmak ve bunların birbirlerinden haberdar olmamasını sağlamak. Pek çok uygulama kendisi çalışırken birtane daha kendisinden çalışmasını istemez bu çakışmadan hoşlanmaz buda çok makul bir istek. Ama sizin ve benim gibi bazı ileri kafalar bir takım fantaziler için bazen bu kuralı aşmak ister. Bu durumda yapmamız gereken şey ikinci growtopia sekmesinin ilkinin var olduğundan haberdar olmamasını sağlamak Tamam da nasıl yapıcam dediğinizi duyar gibiyim. Açıkçası bu growtopia nın kendinin zaten açık olup olmadığını nasıl anlamaya çalıştığına göre değişir kanımca. Daha önce hiç böyle bir şeyle uğraşmadığım için genel geçer bir kural varsa bilmiyorum yani size tecrübelerimi aktaramam yok çünkü. Ama birkaç varsayım yapabilirim:  
  
Yürütülen process ler arasında growtopia.exe ismini görünce kapanıyor olabilir eğer böyleyse açtığınız exe nin ismini değiştirmeyi deneyebilirsiniz ama bu kadarla sınırlı değildir  
  
Mutex kontrolü yapabilir bu konuyu araştırabilirsiniz  
  
Pencere isimlerini okuyor olabilir.  
  
  
  
Biraz internette araştırma yaptım:  
  

### [How to check if another instance of the application is running](https://stackoverflow.com/questions/6392031/how-to-check-if-another-instance-of-the-application-is-running)

Could someone show how it is possible to check whether another instance of the program (e.g. test.exe) is running and if so stop the application from loading if there is an existing instance of it.					stackoverflow.com
				Burda Mutex ve process kontrolleri üzerinde durulmuş.  
  
Sonra bu işlem için growtopia oyununun popüler spam uygulaması (bizzat growtopia kariyerimi bitiren tool aynı zamanda) GABB ı incelemeye karar verdim.  
GABB ın arayüzü:  

![cn8dxnz.png](/pictures/tht/cn8dxnz.png)

  
  
Kaynak kodu .NET ile yazılmış bu yüzden çok kolay bir şekilde okuyabilirim neler yapmaya çalıştığını belki bize de fikir verir yapmak istediğimiz şeye dair ve internette GABB yazan her şeyi indirmeye başladım nerdeyse hepsi virüslüydü Örnek:  
  

![gpf13vq.png](/pictures/tht/gpf13vq.png)

  
sanırım 2023 yılında birileri hala save dosyalarının peşinde  
  
yaklaşık bir saat sonra virüs olmadığını düşündüğüm bir GABB projesi buldum ve bunu analiz etmeye başladım.  
Onu Dnspy atar atmaz bir şeylerin farklı olduğunu hissetmiştim:  
  
  

![l11nec2.png](/pictures/tht/l11nec2.png)

  
Sol tarafta projenin içindeki metodların adını görebilirsiniz, biraz tuhaf değil mi? c++ dan alıştığımız metodlar gözükmekte ama bu bir c# exe siydi hani (?) Sağ tarafta gördüğünüz kod GABB ın OPEN butonuna basıldığında çalışan fonksiyon, gördüğünüz gibi çokca c++ çağrısı gözükmekte o noktada bunun c++ ile yazılmış ama .net olarak derlenmek üzere konfigüre edilmiş bir proje olduğunu düşündüm. Ve daha fazla bilgi edinebilmek umuduyla github da ki GABB projelerini incelemeye başladım ve bunu buldum: [GitHub - SrMotion/GABB-Source: Edited Growtopia Gabb Source](https://github.com/SrMotion/GABB-Source)  
Bu projeyi visual studio ile açtığımda aslında GABB dediğimiz programın gerçekten de c++ ile yazılmış olduğunu gördüm. İki bölümden oluşuyor exe ve dll, exe bizim dnspy ile gördüğümüz kısım dll ise GDLL.dll ve exe kullandığı fonksiyonları burdan tahsis ediyor.  
GABB ın main fonksiyonu böyle mesela:  
  

![cdaunyu.png](/pictures/tht/cdaunyu.png)

  
Bu yapıyı gerçekten ilk defa görüyorum ama anladığım kadarıyla GABB .net olarak derlenebilecek şekilde c++ ile yazılmış (daha fazla saçmalamıyım cidden emin değilim çünkü)  
  
Bu da GABB ın GBDLL.dll den fonksiyonları export ettiğinin kanıtı olan bölümü:  

![ni3sycl.png](/pictures/tht/ni3sycl.png)

  
Biraz yukarı giderseniz dnspy a koyduğum GABB ss inden bahsediyorum. Orda OPEN butonuna basınca hangi fonksiyonun çalıştığını göstermiştim en aşağıda NewWindow fonksiyonunun çağrıldığını görebilirsiniz. Bu fonksiyon GABB ın growtopia dan bissürü açabilmek için kullandığı fonksiyon. Bu noktada GBDLL.dll yi karıştırmam ve içinden NewWindow fonksiyonunun ne yaptığını çıkarmam gerekiyordu bende bunu yaptım.  
  
GBDLL.dll i IDA ya attım ve export ettiği fonksiyonları gördüm:  
  

![94wye4b.png](/pictures/tht/94wye4b.png)

  
  
NewWindow fonksiyonunu görebilirsiniz, işte GABB ın GBDLL.dll den alıp kullandığı bütün metodlar bunlar. Biz bu konuda NewWindow fonksiyonunu yakın merceğe alacağız.  
  

![3p7ohrs.png](/pictures/tht/3p7ohrs.png)

  
Baya bir zaman harcadım ve bu koddan bir şeyler anlamaya çalıştım ama kaçırdığım noktalar vardı ve gerçekten tükenme noktasına geldim. GBDLL.dll in kaynak koduna bakmayı akıl etmek ise 2 günümü aldı  
  

```cpp
void WNDMGR::NewWindow() {
    this->isUpdating = true;
    cout(L"Creating");
    //suspend all;
    for (unsigned int i = 0; i < list.size(); i++) if (!list[i].second->isSuspended()) list[i].second->Suspend(); //1
    //delete mutex;
    this->SetPublicMutex(NULL);
    //add window
    WND * p = new WND(this->filepath);//2

    if (!p->mutexCaught()) {
        p->Kill();
        delete p;
        this->update();
        return;
    }
    this->SetPublicMutex(this->NewPublicMutex());//3
    this->list.push_back({ this->freeID(), p });
    for (unsigned int i = 0; i < list.size(); i++) if (list[i].second->isSuspended()) list[i].second->Resume();//4
    this->isUpdating = false;
    if (this->list.size()) this->list[this->list.size() - 1].second->setTitle(L"Growtopia [" + std::to_wstring(this->list[this->list.size() - 1].first) + L"]");//5
    this->update();
}
```

  
Burda ki bazı windows api leri fonksiyonlara sarıldığı için ve o fonksiyonların kodunu atmak da çirkin olacağı için (isteyen github dan baksın linkini bıraktım yukarda) ben size kısaca burda ne döndüğünü açıklayayım (numaralandırarak anlatıcam):  
  
//1  bir for döngüsünün bir listeyi döndüğünü görebilirsiniz bu liste kodun içerisinde açılan her bir growtopia penceresinin handle bilgilerini içeriyor kısaca, ve for döngüsü sayesinde hepsi suspend ediliyor SuspendThread windows api si kullanılarak. Bunun neden yapıldığını açıklayacağım.  
  
//2  bizim asıl istediğim şey var bir nesne oluştuğunu görebilirsiniz bu nesne yeni oluşan growtopia penceresinin handle bilgisi, evet yanlış duymadınız growtopia yı tam olarak bu satırda başlatıyoruz o yüzden bunun içine girmemiz gerekiyor işler biraz karışabilir sıkı durun.  
  

```cpp
WND::WND(std::wstring filepath) {
    if (CreateProcess(filepath.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &this->SI, &this->PI)) { //2.1
        int limit = 100;
        HWND HWNDResult = NULL;
        while (HWNDResult == NULL && limit > 0) {
            HWNDResult = EnumWindowsMyGt(this->PI.dwProcessId); //2.2
            limit++;
            Sleep(100);
        }
        if (HWNDResult != NULL) {
            this->wnd = HWNDResult;
        }
        else {
            this->Kill();
            this->wnd = NULL;
            return;
        }

        DWORD exit_code;
        GetExitCodeProcess(this->PI.hProcess, &exit_code); //2.3
        if (exit_code != 259) return;

        this->mutex_caught = false;
        if (EnumerateHandles(this->PI.dwProcessId, this->PI.hProcess) != 0) { //2.4
            this->Kill();
        }
        else this->mutex_caught = true;
    }
}
```

  
//2.1 Bu kodda growtopia process nin başlatıldığını görebilirsiniz (CreateProcess apisi ile).  
//2.2 Burda yapılan şey, açtığımız process ile aynı pid e sahip ve ismi "Growtopia" olan pencere yi bulana kadar yani createprocess ile açtığımız programın penceresini bulana kadar while loop unun içinde dönmek (birde limit belirtilmiş sonsuza kadar beklemesin diye, max 100 tur loop edilicek yani). (Pencere ismi ve pid kontrolü EnumWindowsMyGt içinde yapılıyor dilerseniz bakabilirsiniz)  
//2.3 Burda biraz önce oluşturduğumuz growtopia process inin hala aktif olup olmadığını kontrol ediyoruz. (GetExitCodeProcess bir windows apisidir ve bize int main fonksiyonundan dönen değeri sağlar kendisine verdiğimiz process id sine tekabül eden işlem için)  
//2.4 Dalmayın! Önemli yerlerdeyiz bu fonksiyon tam olarak bypass ın yapıldığı yere gidiyor biraz uzun olduğu için kodu buraya koymıcam ama sizin şuan ona baktığınızı varsayarak açıklıyorum:  
Anlık olarak işletim sisteminde çalışan tüm handle lerı  NtQuerySystemInformation windows api si ile topluyoruz ve bunlardan biraz önce açmış olduğumuz growtopia process inin pid i ile kendi pid leri aynı olan handle lerı filtreliyoruz sonra bunların arasında "Mutant" olanları (Yani CreateMutex ile oluşan Mutex) ve içinde "Growtopia" kelimesi geçenleri de ayrıeten filtreliyip bunları DuplicateHandle windows api si ile (ayrıntıya girmicem) kapatıyoruz. Bu sayede Mutex ten kurtulmuş oluyoruz.  
  
Peki biz "Growtopia" adında bir Mutex ın varlığını ve bunun önemini nerden biliyoruz? Growtopia nın kendisinden bir tane daha açılmasını önlemek için Mutex oluşturduğunu ve bunun varlığını kontrol edip eğer varsa yeni process ini sonlandırdığını nerden biliyoruz? Bunu Growtopia nın kaynak koduna baktığımız zaman görüyoruz ama şuankine bakmanız biraz zor çünkü vmprotect ile korumuş p*ştlar o yüzden şu konuya bakmanız gerekmekte -> [GitHub - TomiyokaTanaka/growtopia_cracked: Reverse engineering a game by binary patching the game so that it can open multiple instances](https://github.com/TomiyokaTanaka/growtopia_cracked)  
Burdaki arkadaşımız Growtopia kendisini vmprotect ile korumadan önce onu ghidra ya atmış ve instance kontrol mekanizmasını bir güzel analiz etmiş. Görüldüğü üzere Growtopia nın içinde şu tarz bir kod bulunuyor:  
program_handle = OpenMutexA(0x1f0001,0,"Growtopia");  
if ((program_handle == (HANDLE)0x0))  
    program_handle = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,0,"Growtopia");  
    //Oyunun kodları burdan devam ediyor  
else:  
   MessageBoxA((HWND)0x0,"An instance of Growtopia is already running!  Go play that one.", "Growtopia",0);  
   //Buranın sonu ise boklu dere, kapanıyor program  
  
Yani growtopia sistemde halihazırda "Growtopia" adında bir mutex varsa çalışmıyor işte GABB da burda devreye giriyor ve yeni başlattığı process daha açılmadan üstte anlattığım şekilde Mutex ten kurtuluyor. Ama sadece bunu yapması Growtopia nın gene hata vermesine yol açıyor bunu kendim tecrübe ettim.  

![imd012w.png](/pictures/tht/imd012w.png)

  
Çünkü growtopia çalışma esnasında bu mutex in varlığını kontrol ediyor olsa gerek ve onu göremediğinde hata veriyor çünkü olması lazımdı! Bu yüszden biz ikinci bir gorwtopia process i açmak için onu silip geri yerine koymazsak yukardaki hatayı alıyoruz. İşte GABB bu yüzden //3 numarada böyle yapıyor kendisi "Growtopia" adında bir mutex oluşturuyor ama bunu tamda tüm mutex leri sildikten sonra yapıyor işte bu olay growtopia nın başlangıçta yaptığı kontrolü aşmamızı sağlıyor çünkü growtopia penceresi oluşturulduğu an "Growtopia" adındaki mutex(ler) i siliyoruz ve hemen ardından kendimiz bir tane oluşturuyoruz buda growtopia nın üsteki ss deki gibi crash olmamasını sağlıyor.  
Eveet... //4 numaraya geldik burda ResumeThread windows apisi kullanılarak topladığımız tüm growtopia process leri tekrardan resume ediliyor. Tüm işlemler başlamadan öncede suspend edilmişlerdi ve size bunu açıklayacağımı söylemiştim şimdi söyleyebilirim sanırım. GABB ın böyle yapmasının sebebi yeni bir growtopia process i oluşturulurken halihazırda çalışan diğer growtopia process lerinin tüm mutex lerin silindiği an varya o anda crash vermelerini engellemek. Bu yüzden onları basitçe pause edip sonra devam ettiriyoruz. Mutex imizi tekrar oluşturunca yani. Evet tüm bu bilgileri topladıktan ve bazı kaynakları özellikle GABB ın kaynak kodunu emcükledikten sonra kendim basitçe bu işlemi yapan tek vasfı yeni pencere açabilmek olan bir kod hazırladım. Bir nevi deney amaçlı. Onuda aşağı bırakacağım. Aklınıza takılan yada benim yanlış anlattığımı düşündüğünüz bir husus varsa gelin yorumlara tartışalım. Bu operasyonuda bu şekilde bitirmiş olduk Selametle kalın.  
[@VuRGuN3666](https://www.turkhackteam.org/uye/1003265/)  
[GitHub - SemsYapar/GrowtopiaMultiInstances: Abaout Bypass Growtopia one instance protection](https://github.com/SemsYapar/GrowtopiaMultiInstances)Mini Deneysel Bypass Kodum (GABB dan araklanmış):  
Konunun videolu anlatımı:  

<iframe width="560" height="315" src="https://www.youtube.com/embed/y4028uGopXI" frameborder="0" allowfullscreen></iframe>
