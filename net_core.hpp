// net_core.hpp - Editor collab icin Geode'dan bagimsiz TCP oturum katmani.
//
// Mantik: bir kisi HOST olur (portu dinler), digerleri IP:port yazarak katilir.
// Radmin VPN / ZeroTier / Tailscale IP'si ile direkt calisir, merkezi sunucu yok.
//
// Thread kurali: Session kendi I/O thread'ini acar. Oyun tarafi (ana thread)
// sadece send()/sendTo()/poll()/peers() cagirir. GD/Cocos fonksiyonlarini
// ASLA I/O thread'inden cagirma - hepsi poll() ile ana thread'de islenir.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace collab {

constexpr uint16_t kProtocolVersion = 1;
constexpr uint16_t kDefaultPort = 47820;
constexpr uint32_t kHostId = 1;                    // host'un peer id'si hep 1
constexpr uint32_t kMaxFrame = 64u * 1024u * 1024u; // tek paket ust siniri (64 MB)
constexpr size_t kMaxPeers = 32;                   // host dahil degil

enum class MsgType : uint8_t {
    Hello = 1,      // istemci -> host: surum + isim
    Welcome = 2,    // host -> istemci: sana verilen id + odadakiler
    PeerJoined = 3, // host -> herkes
    PeerLeft = 4,   // host -> herkes
    LevelData = 5,  // level verisi (uygulama tanimlar), role EDILMEZ
    Cursor = 6,     // imlec konumu, host digerlerine role eder
    Op = 7,         // editor islemi (koy/sil/tasi...), host digerlerine role eder
    Ping = 8,
    Pong = 9,
    Kick = 10,      // host -> istemci: sebep yazisi
    Chat = 11,      // kisa mesaj, role edilir
};

struct Message {
    MsgType type{};
    uint32_t from = 0; // gonderen peer id (host'tan gelende host role ettigi kisinin id'si)
    std::vector<uint8_t> payload;
};

struct PeerInfo {
    uint32_t id = 0;
    std::string name;
    int rttMs = -1; // bilinmiyorsa -1
    bool isHost = false;
};

struct Event {
    enum class Kind {
        Connected,    // (istemci) host'a baglandin, peerId = senin id'n
        Disconnected, // (istemci) baglanti koptu, text = sebep
        PeerJoined,   // biri odaya girdi (peerId, text = isim)
        PeerLeft,     // biri cikti (peerId, text = isim)
        Received,     // uygulama mesaji geldi (msg)
        Error,        // baglanamadi vs. (text)
    };
    Kind kind{};
    uint32_t peerId = 0;
    std::string text;
    Message msg;
};

// ---- Paket icerigi yazma/okuma (little-endian, sinir kontrollu) ----
class Writer {
public:
    Writer& u8(uint8_t v);
    Writer& u16(uint16_t v);
    Writer& u32(uint32_t v);
    Writer& i32(int32_t v);
    Writer& u64(uint64_t v);
    Writer& f32(float v);
    Writer& str(const std::string& s);                 // u16 uzunluk + bayt (max 65535)
    Writer& bytes(const std::vector<uint8_t>& b);      // u32 uzunluk + bayt
    std::vector<uint8_t> take() { return std::move(buf_); }
    const std::vector<uint8_t>& data() const { return buf_; }
private:
    std::vector<uint8_t> buf_;
};

class Reader {
public:
    explicit Reader(const std::vector<uint8_t>& d) : d_(d) {}
    uint8_t u8();
    uint16_t u16();
    uint32_t u32();
    int32_t i32();
    uint64_t u64();
    float f32();
    std::string str();
    std::vector<uint8_t> bytes();
    bool ok() const { return ok_; }           // okurken tasma olduysa false
    size_t remaining() const { return d_.size() - pos_; }
private:
    bool need(size_t n);
    const std::vector<uint8_t>& d_;
    size_t pos_ = 0;
    bool ok_ = true;
};

// ---- Imlec paketi yardimcilari ----
struct CursorState {
    float x = 0.f; // LEVEL koordinati (ekran degil) - kaydirma/zoom'dan bagimsiz olsun
    float y = 0.f;
    uint8_t flags = 0; // bit0 = fare basili
};
std::vector<uint8_t> encodeCursor(const CursorState& c);
bool decodeCursor(const std::vector<uint8_t>& payload, CursorState& out);

// ---- Oturum ----
class Session {
public:
    Session();
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Host ol. port=0 verirsen bos bir port secer (port() ile ogren).
    bool host(uint16_t port, const std::string& playerName, std::string& err);

    // Host'a katil. ASENKRON: hemen doner, sonucu poll() ile Connected / Error olarak alirsin.
    // address: IP ("26.12.34.56") veya alan adi.
    void join(const std::string& address, uint16_t port, const std::string& playerName);

    void stop();
    bool running() const;
    bool isHost() const;
    uint32_t myId() const;   // host'ta 1, istemcide Connected'tan sonra gecerli
    uint16_t port() const;   // host'ta dinlenen port

    // Host: herkese yollar. Istemci: host'a yollar (Cursor/Op/Chat'i host digerlerine role eder).
    void send(MsgType type, std::vector<uint8_t> payload);
    // Sadece host: tek kisiye yollar (ornegin yeni gelene LevelData).
    void sendTo(uint32_t peerId, MsgType type, std::vector<uint8_t> payload);
    // Sadece host: birini at.
    void kick(uint32_t peerId, const std::string& reason);

    // Ana thread'de her frame cagir: bekleyen olaylari tek tek ver.
    bool poll(Event& out);

    std::vector<PeerInfo> peers() const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
};

// "ip:port" yaz-coz. Port yoksa defPort kullanilir. Basarisizsa false.
bool parseAddress(const std::string& text, std::string& host, uint16_t& port, uint16_t defPort = kDefaultPort);

} // namespace collab
