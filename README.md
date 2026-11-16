# Editor Collab - ağ çekirdeği (AiLevelStudio için)

Geode'dan bağımsız, sadece standart C++17 + işletim sistemi soketleri. Ek kütüphane yok.

## Dosyalar
| Dosya | Ne işe yarıyor |
|---|---|
| `net_core.hpp/.cpp` | Host/katıl, paket çerçeveleme, imleç/op röle, ping, kick, olay kuyruğu |
| `local_ips.hpp/.cpp` | Bu bilgisayarın IP'lerini listeler, Radmin/Hamachi/Tailscale/ZeroTier'i işaretler |
| `test_main.cpp` | 132 kontrol (Linux'ta çalıştırıldı) |
| `assets/logo.png` | Mod logosu (336x336), `logo.svg` kaynak dosya |
| `assets/collab_btn*.png` | Editör butonu (40 / 80 / 160 px: normal, -hd, -uhd) |

## Projeye ekleme (CMakeLists.txt)
```cmake
target_sources(${PROJECT_NAME} PRIVATE
    src/collab/net_core.cpp
    src/collab/local_ips.cpp)

if (WIN32)
    target_link_libraries(${PROJECT_NAME} ws2_32 iphlpapi)
endif()
```

## Kullanım
```cpp
#include "collab/net_core.hpp"
#include "collab/local_ips.hpp"

static collab::Session g_session;

// --- Pencerede "kendi IP'ni göster" ---
auto addrs = collab::listLocalAddresses();          // sanal ağlar başta
std::string share = collab::bestShareAddress(addrs); // arkadaşlara verilecek IP
// her satır için: a.ip, a.ifaceName, collab::kindLabel(a.kind), a.isVirtual

// --- Host ol ---
std::string err;
if (!g_session.host(collab::kDefaultPort, accountName, err)) { /* err'i göster */ }

// --- Katıl (IP kutusuna yazılan metin) ---
std::string h; uint16_t p;
if (collab::parseAddress(ipText, h, p)) g_session.join(h, p, accountName);

// --- ANA THREAD'de her frame (ör. EditorUI::update hook'u veya scheduler) ---
collab::Event e;
while (g_session.poll(e)) {
    switch (e.kind) {
        case collab::Event::Kind::Connected:    /* e.peerId = senin id'n */ break;
        case collab::Event::Kind::PeerJoined:   /* e.peerId, e.text = isim -> level verisini yolla */
            if (g_session.isHost()) g_session.sendTo(e.peerId, collab::MsgType::LevelData, levelBytes);
            break;
        case collab::Event::Kind::PeerLeft:     /* imleci sil */ break;
        case collab::Event::Kind::Received:
            if (e.msg.type == collab::MsgType::Cursor) {
                collab::CursorState c;
                if (collab::decodeCursor(e.msg.payload, c)) { /* e.msg.from'un imlecini c.x,c.y'ye taşı */ }
            }
            break;
        case collab::Event::Kind::Disconnected: /* e.text = sebep */ break;
        case collab::Event::Kind::Error:        /* e.text = sebep */ break;
    }
}

// --- İmleç gönder (saniyede ~20 kez yeter, LEVEL koordinatıyla) ---
g_session.send(collab::MsgType::Cursor, collab::encodeCursor({levelX, levelY, 0}));
```

**Kural:** GD/Cocos fonksiyonlarını asla ağ thread'inden çağırma. `Session` zaten sadece
`poll()` ile olay verir, yani senin kodun hep ana thread'de çalışır.

## Protokol (özet)
Her paket: `u32 uzunluk | u8 tür | u32 gönderen | içerik` (little-endian).
- İstemci `Hello(sürüm, isim)` yollar, host `Welcome(id, odadakiler)` döner. Host'un id'si hep 1.
- `Cursor`, `Op`, `Chat`: istemciden gelince host diğerlerine röle eder (gönderene geri yollamaz).
- `LevelData`: röle edilmez, host `sendTo` ile tek kişiye yollar.
- 2 sn'de bir ping, 10 sn sessizlik = kopma. Tek paket en fazla 64 MB. Oda en fazla 32 kişi.
- Yavaş bağlantıda imleç paketleri atlanır (gecikme birikmesin diye), `Op` paketleri asla atlanmaz.

## Bilinen sınırlar
- **Windows kodu burada derlenemedi** (bu ortamda mingw yok). Linux'ta ASan/UBSan/TSan ile temiz.
  Windows'a özel kısımlar `#ifdef _WIN32` içinde, Geode CI'ında derlenince küçük bir düzeltme çıkabilir.
- Sadece IPv4. Şifre/yetki yok: IP'yi bilen herkes girebilir, o yüzden sanal ağ (Radmin vb.) içinde kullan.
- Şimdilik `Op` içeriği opak bayt dizisi; koy/sil/taşı formatını editör hook'larını yazarken belirleyeceğiz.
- `listLocalAddresses` Wine/Proton altında Windows API'sini kullanır; sonuç boş gelirse IP'yi elle yazma kutusu hep açık kalmalı.
