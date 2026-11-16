// test_main.cpp - net_core + local_ips testleri (Linux/macOS'ta calisir)
#include "local_ips.hpp"
#include "net_core.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <thread>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace collab;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (cond) g_pass++;                                                      \
        else {                                                                   \
            g_fail++;                                                            \
            std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);        \
        }                                                                        \
    } while (0)

struct Node {
    Session s;
    std::vector<Event> log;
    void drain() {
        Event e;
        while (s.poll(e)) log.push_back(std::move(e));
    }
    size_t count(Event::Kind k) const {
        size_t n = 0;
        for (auto& e : log) n += (e.kind == k);
        return n;
    }
    size_t countRecv(MsgType t) const {
        size_t n = 0;
        for (auto& e : log) n += (e.kind == Event::Kind::Received && e.msg.type == t);
        return n;
    }
    const Event* find(Event::Kind k, uint32_t id = 0) const {
        for (auto& e : log)
            if (e.kind == k && (id == 0 || e.peerId == id)) return &e;
        return nullptr;
    }
};

static bool pumpUntil(std::vector<Node*> nodes, int timeoutMs, const std::function<bool()>& done) {
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < end) {
        for (auto* n : nodes) n->drain();
        if (done()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    for (auto* n : nodes) n->drain();
    return done();
}

static void pumpFor(std::vector<Node*> nodes, int ms) {
    pumpUntil(nodes, ms, [] { return false; });
}

static std::vector<uint8_t> seqPayload(uint32_t i) {
    Writer w;
    w.u32(i);
    return w.take();
}

// ---------------------------------------------------------------- testler

static void testCodec() {
    std::printf("[codec]\n");
    Writer w;
    w.u8(7).u16(65000).u32(0xDEADBEEF).i32(-5).u64(0x0123456789ABCDEFull).f32(3.5f).str("Ahmet-ğüşi").bytes({1, 2, 3});
    auto buf = w.take();
    Reader r(buf);
    CHECK(r.u8() == 7);
    CHECK(r.u16() == 65000);
    CHECK(r.u32() == 0xDEADBEEF);
    CHECK(r.i32() == -5);
    CHECK(r.u64() == 0x0123456789ABCDEFull);
    CHECK(r.f32() == 3.5f);
    CHECK(r.str() == "Ahmet-ğüşi");
    CHECK(r.bytes() == (std::vector<uint8_t>{1, 2, 3}));
    CHECK(r.ok());
    CHECK(r.remaining() == 0);
    r.u8(); // fazla okuma
    CHECK(!r.ok());

    // yalan uzunluk: str() 60000 bayt vaat ediyor ama yok
    std::vector<uint8_t> bad = {0x60, 0xEA, 'a'};
    Reader r2(bad);
    CHECK(r2.str().empty());
    CHECK(!r2.ok());

    CursorState c{12.25f, -300.5f, 1}, d;
    CHECK(decodeCursor(encodeCursor(c), d));
    CHECK(d.x == 12.25f && d.y == -300.5f && d.flags == 1);
    CHECK(!decodeCursor({1, 2}, d));
}

static void testParseAddress() {
    std::printf("[parseAddress]\n");
    std::string h;
    uint16_t p = 0;
    CHECK(parseAddress("26.12.34.56:47820", h, p) && h == "26.12.34.56" && p == 47820);
    CHECK(parseAddress("  26.1.2.3  ", h, p) && h == "26.1.2.3" && p == kDefaultPort);
    CHECK(parseAddress("my-host.example.com:1234", h, p) && h == "my-host.example.com" && p == 1234);
    CHECK(!parseAddress("", h, p));
    CHECK(!parseAddress("1.2.3.4:", h, p));
    CHECK(!parseAddress("1.2.3.4:0", h, p));
    CHECK(!parseAddress("1.2.3.4:70000", h, p));
    CHECK(!parseAddress("1.2.3.4:abc", h, p));
    CHECK(!parseAddress(":5000", h, p));
    CHECK(!parseAddress("bad host", h, p));
    CHECK(!parseAddress("[::1]:5000", h, p));
}

static void testClassify() {
    std::printf("[classifyAddress]\n");
    CHECK(classifyAddress("Radmin VPN", "26.5.6.7") == NetKind::Radmin);
    CHECK(classifyAddress("Ethernet 3", "26.5.6.7") == NetKind::Radmin);
    CHECK(classifyAddress("Hamachi", "25.1.2.3") == NetKind::Hamachi);
    CHECK(classifyAddress("eth5", "25.1.2.3") == NetKind::Hamachi);
    CHECK(classifyAddress("Tailscale", "100.101.102.103") == NetKind::Tailscale);
    CHECK(classifyAddress("tun0", "100.64.0.1") == NetKind::Tailscale);
    CHECK(classifyAddress("tun0", "100.127.255.254") == NetKind::Tailscale);
    CHECK(classifyAddress("tun0", "100.128.0.1") == NetKind::Other);   // 100.64/10 disinda
    CHECK(classifyAddress("tun0", "100.63.0.1") == NetKind::Other);
    CHECK(classifyAddress("ZeroTier One [8056c2e21c000001]", "10.147.17.5") == NetKind::ZeroTier);
    CHECK(classifyAddress("ztrf2q5xyz", "172.27.1.2") == NetKind::ZeroTier);
    CHECK(classifyAddress("eth0", "192.168.1.20") == NetKind::Lan);
    CHECK(classifyAddress("eth0", "10.0.0.5") == NetKind::Lan);
    CHECK(classifyAddress("eth0", "172.16.5.5") == NetKind::Lan);
    CHECK(classifyAddress("eth0", "172.31.255.1") == NetKind::Lan);
    CHECK(classifyAddress("eth0", "172.32.0.1") == NetKind::Other);
    CHECK(classifyAddress("eth0", "8.8.8.8") == NetKind::Other);
    CHECK(classifyAddress("eth0", "not-an-ip") == NetKind::Other);

    auto list = listLocalAddresses();
    std::printf("  bu makinedeki adresler (%zu):\n", list.size());
    for (auto& a : list) std::printf("    %-14s %-16s %s%s\n", a.ifaceName.c_str(), a.ip.c_str(), kindLabel(a.kind), a.isVirtual ? " [sanal]" : "");
    for (auto& a : list) CHECK(a.ip.rfind("127.", 0) != 0 && a.ip.rfind("169.254.", 0) != 0);
    // siralama: sanal olanlar LAN'dan once
    bool seenNonVirtual = false, order = true;
    for (auto& a : list) {
        if (!a.isVirtual) seenNonVirtual = true;
        else if (seenNonVirtual) order = false;
    }
    CHECK(order);

    std::vector<LocalAddress> fake = {{"eth0", "192.168.1.5", NetKind::Lan, false}, {"Radmin VPN", "26.1.1.1", NetKind::Radmin, true}};
    CHECK(bestShareAddress(fake) == "26.1.1.1");
    fake.erase(fake.begin() + 1);
    CHECK(bestShareAddress(fake) == "192.168.1.5");
    fake.clear();
    CHECK(bestShareAddress(fake).empty());
}

static void testSession() {
    std::printf("[session: el sikisma, role, buyuk veri, siralama]\n");
    Node host, a, b;
    std::string err;
    CHECK(host.s.host(0, "HostAdam", err));
    uint16_t port = host.s.port();
    CHECK(port != 0);
    CHECK(host.s.isHost());
    CHECK(host.s.myId() == kHostId);

    a.s.join("127.0.0.1", port, "  Ali\x01  ");
    CHECK(pumpUntil({&host, &a, &b}, 3000, [&] { return a.count(Event::Kind::Connected) == 1; }));
    b.s.join("127.0.0.1", port, std::string(80, 'x')); // cok uzun isim
    CHECK(pumpUntil({&host, &a, &b}, 3000, [&] { return b.count(Event::Kind::Connected) == 1 && host.count(Event::Kind::PeerJoined) == 2 && a.count(Event::Kind::PeerJoined) >= 2; }));

    CHECK(a.find(Event::Kind::Connected)->peerId == 2);
    CHECK(b.find(Event::Kind::Connected)->peerId == 3);
    CHECK(a.s.myId() == 2 && b.s.myId() == 3);
    // isim temizligi
    CHECK(host.find(Event::Kind::PeerJoined, 2)->text == "Ali");
    CHECK(host.find(Event::Kind::PeerJoined, 3)->text == std::string(32, 'x'));
    // B'nin roster'i: host (1) + Ali (2)
    CHECK(b.find(Event::Kind::PeerJoined, 1) && b.find(Event::Kind::PeerJoined, 1)->text == "HostAdam");
    CHECK(b.find(Event::Kind::PeerJoined, 2) && b.find(Event::Kind::PeerJoined, 2)->text == "Ali");
    // A'ya sonradan B girdi
    CHECK(a.find(Event::Kind::PeerJoined, 3) != nullptr);
    // peers() kendimizi de icerir
    CHECK(host.s.peers().size() == 3);
    CHECK(a.s.peers().size() == 3);
    CHECK(b.s.peers().size() == 3);

    // --- imlec: A -> host + B (A'ya geri yansimaz)
    a.s.send(MsgType::Cursor, encodeCursor({100.5f, 200.25f, 1}));
    CHECK(pumpUntil({&host, &a, &b}, 2000, [&] { return host.countRecv(MsgType::Cursor) == 1 && b.countRecv(MsgType::Cursor) == 1; }));
    pumpFor({&host, &a, &b}, 100);
    CHECK(a.countRecv(MsgType::Cursor) == 0);
    for (Node* n : {&host, &b}) {
        for (auto& e : n->log) {
            if (e.kind == Event::Kind::Received && e.msg.type == MsgType::Cursor) {
                CHECK(e.msg.from == 2);
                CursorState c;
                CHECK(decodeCursor(e.msg.payload, c) && c.x == 100.5f && c.y == 200.25f && c.flags == 1);
            }
        }
    }

    // --- host Op yayinlar: herkes from=1 ile alir
    host.s.send(MsgType::Op, {9, 9, 9});
    CHECK(pumpUntil({&host, &a, &b}, 2000, [&] { return a.countRecv(MsgType::Op) == 1 && b.countRecv(MsgType::Op) == 1; }));
    for (Node* n : {&a, &b})
        for (auto& e : n->log)
            if (e.kind == Event::Kind::Received && e.msg.type == MsgType::Op) CHECK(e.msg.from == kHostId && e.msg.payload.size() == 3);

    // --- LevelData role EDILMEZ: A host'a yollar, B gormez
    a.s.send(MsgType::LevelData, {1, 2, 3});
    CHECK(pumpUntil({&host, &a, &b}, 2000, [&] { return host.countRecv(MsgType::LevelData) == 1; }));
    pumpFor({&host, &a, &b}, 100);
    CHECK(b.countRecv(MsgType::LevelData) == 0);

    // --- buyuk veri: host -> sadece A'ya 8 MB
    std::vector<uint8_t> big(8 * 1024 * 1024);
    uint32_t x = 12345;
    for (auto& v : big) {
        x = x * 1664525u + 1013904223u;
        v = (uint8_t)(x >> 24);
    }
    host.s.sendTo(2, MsgType::LevelData, big);
    CHECK(pumpUntil({&host, &a, &b}, 8000, [&] { return a.countRecv(MsgType::LevelData) == 1; }));
    pumpFor({&host, &a, &b}, 100);
    CHECK(b.countRecv(MsgType::LevelData) == 0);
    bool same = false;
    for (auto& e : a.log)
        if (e.kind == Event::Kind::Received && e.msg.type == MsgType::LevelData) same = (e.msg.payload == big);
    CHECK(same);

    // --- siralama: A 3000 Op yollar, host ve B ayni sirada almali
    for (uint32_t i = 0; i < 3000; i++) a.s.send(MsgType::Op, seqPayload(i));
    CHECK(pumpUntil({&host, &a, &b}, 8000, [&] { return host.countRecv(MsgType::Op) == 3000 && b.countRecv(MsgType::Op) == 3001; })); // +1: host'un yukaridaki Op'u
    for (Node* n : {&host, &b}) {
        uint32_t expect = 0;
        bool inOrder = true;
        for (auto& e : n->log) {
            if (e.kind == Event::Kind::Received && e.msg.type == MsgType::Op && e.msg.payload.size() == 4) {
                Reader r(e.msg.payload);
                if (r.u32() != expect++) inOrder = false;
            }
        }
        CHECK(inOrder);
        CHECK(expect == 3000);
    }

    // --- ping/rtt olusmus mu
    std::this_thread::sleep_for(std::chrono::milliseconds(2300));
    pumpFor({&host, &a, &b}, 50);
    bool rttOk = false;
    for (auto& p : host.s.peers())
        if (p.id == 2) rttOk = p.rttMs >= 0 && p.rttMs < 500;
    CHECK(rttOk);

    // --- B cikar: host ve A PeerLeft gormeli
    b.s.stop();
    CHECK(pumpUntil({&host, &a}, 3000, [&] { return host.count(Event::Kind::PeerLeft) == 1 && a.count(Event::Kind::PeerLeft) == 1; }));
    CHECK(host.find(Event::Kind::PeerLeft)->peerId == 3);
    CHECK(a.find(Event::Kind::PeerLeft)->peerId == 3);
    CHECK(host.s.peers().size() == 2);
    CHECK(a.s.peers().size() == 2);

    // --- host A'yi atar
    host.s.kick(2, "gule gule");
    CHECK(pumpUntil({&host, &a}, 3000, [&] { return a.count(Event::Kind::Disconnected) == 1 && host.count(Event::Kind::PeerLeft) == 2; }));
    CHECK(a.find(Event::Kind::Disconnected)->text == "gule gule");
    CHECK(!a.s.running());

    // --- host kapanirsa istemci Disconnected gormeli
    Node c;
    c.s.join("127.0.0.1", port, "Cem");
    CHECK(pumpUntil({&host, &c}, 3000, [&] { return c.count(Event::Kind::Connected) == 1; }));
    host.s.stop();
    CHECK(pumpUntil({&c}, 3000, [&] { return c.count(Event::Kind::Disconnected) == 1; }));
    CHECK(!c.s.running());
}

static void testConnectFail() {
    std::printf("[baglanti hatasi]\n");
    Node n;
    n.s.join("127.0.0.1", 1, "Kimse"); // port 1: kimse dinlemiyor
    CHECK(pumpUntil({&n}, 8000, [&] { return n.count(Event::Kind::Error) == 1; }));
    CHECK(n.count(Event::Kind::Connected) == 0);
    CHECK(!n.s.running());

    Node m;
    m.s.join("bu-alan-adi-yok.invalid", 47820, "Kimse");
    CHECK(pumpUntil({&m}, 10000, [&] { return m.count(Event::Kind::Error) == 1; }));

    // port zaten kullanimda
    Node h1, h2;
    std::string err;
    CHECK(h1.s.host(0, "A", err));
    CHECK(!h2.s.host(h1.s.port(), "B", err));
    CHECK(!err.empty());
}

#ifndef _WIN32
static int rawConnect(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (::connect(fd, (sockaddr*)&sa, sizeof(sa)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

static bool rawSendAll(int fd, const std::vector<uint8_t>& d) {
    size_t off = 0;
    while (off < d.size()) {
        ssize_t n = ::send(fd, d.data() + off, d.size() - off, MSG_NOSIGNAL);
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

// Bir frame okumaya calis (zaman asimiyla). kapaninca/okunamazsa false.
static bool rawReadFrame(int fd, int timeoutMs, uint8_t& type, std::vector<uint8_t>& payload) {
    auto readN = [&](uint8_t* dst, size_t n) {
        size_t got = 0;
        auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        while (got < n) {
            if (std::chrono::steady_clock::now() > end) return false;
            ssize_t r = ::recv(fd, dst + got, n - got, MSG_DONTWAIT);
            if (r > 0) got += (size_t)r;
            else if (r == 0) return false;
            else std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return true;
    };
    uint8_t hdr[4];
    if (!readN(hdr, 4)) return false;
    uint32_t len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    if (len < 5 || len > 1000000) return false;
    std::vector<uint8_t> body(len);
    if (!readN(body.data(), len)) return false;
    type = body[0];
    payload.assign(body.begin() + 5, body.end());
    return true;
}

static std::vector<uint8_t> rawFrame(uint8_t type, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> f;
    uint32_t len = (uint32_t)(5 + payload.size());
    for (int i = 0; i < 4; i++) f.push_back((uint8_t)(len >> (8 * i)));
    f.push_back(type);
    for (int i = 0; i < 4; i++) f.push_back(0);
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

static void testHostile() {
    std::printf("[kotu niyetli / bozuk istemciler]\n");
    Node host;
    std::string err;
    CHECK(host.s.host(0, "Host", err));
    uint16_t port = host.s.port();

    // 1) Devasa uzunluk basligi
    int fd = rawConnect(port);
    CHECK(fd >= 0);
    CHECK(rawSendAll(fd, {0xFF, 0xFF, 0xFF, 0xFF, 1, 0, 0, 0, 0}));
    uint8_t t;
    std::vector<uint8_t> pl;
    CHECK(!rawReadFrame(fd, 1500, t, pl)); // host baglantiyi kapatmali
    ::close(fd);

    // 2) El sikismadan once baska paket
    fd = rawConnect(port);
    CHECK(rawSendAll(fd, rawFrame((uint8_t)MsgType::Op, {1, 2, 3})));
    CHECK(!rawReadFrame(fd, 1500, t, pl));
    ::close(fd);

    // 3) Yanlis surumle Hello -> Kick + kapanma
    fd = rawConnect(port);
    Writer w;
    w.u16(999).str("Eski");
    CHECK(rawSendAll(fd, rawFrame((uint8_t)MsgType::Hello, w.data())));
    CHECK(rawReadFrame(fd, 2000, t, pl));
    CHECK(t == (uint8_t)MsgType::Kick);
    Reader r(pl);
    CHECK(r.str().find("Version mismatch") != std::string::npos);
    ::close(fd);

    // 4) Sahte PeerJoined/PeerLeft gonderen istemci etkisiz olmali
    Node good;
    good.s.join("127.0.0.1", port, "Iyi");
    CHECK(pumpUntil({&host, &good}, 3000, [&] { return good.count(Event::Kind::Connected) == 1; }));
    fd = rawConnect(port);
    Writer hello;
    hello.u16(kProtocolVersion).str("Sahtekar");
    CHECK(rawSendAll(fd, rawFrame((uint8_t)MsgType::Hello, hello.data())));
    CHECK(rawReadFrame(fd, 2000, t, pl));
    CHECK(t == (uint8_t)MsgType::Welcome);
    Writer fake;
    fake.u32(2).str("Hayalet");
    rawSendAll(fd, rawFrame((uint8_t)MsgType::PeerLeft, fake.data()));  // "Iyi" (id 2) cikti gibi gostermeye calis
    rawSendAll(fd, rawFrame((uint8_t)MsgType::Kick, fake.data()));
    pumpFor({&host, &good}, 300);
    CHECK(good.count(Event::Kind::PeerLeft) == 0);
    CHECK(host.count(Event::Kind::PeerLeft) == 0);
    ::close(fd);

    // 5) Yarim kalan baglanti: hic bir sey gondermeden bekle -> handshake timeout (8 sn)
    //    (testi uzatmamak icin sadece baglanti acik kalirken host'un diger istemcilere hizmet verdigini kontrol ediyoruz)
    int idle = rawConnect(port);
    Node late;
    late.s.join("127.0.0.1", port, "Gec");
    CHECK(pumpUntil({&host, &late, &good}, 3000, [&] { return late.count(Event::Kind::Connected) == 1; }));
    ::close(idle);

    // Host hala saglam
    good.s.send(MsgType::Chat, {'h', 'i'});
    CHECK(pumpUntil({&host, &good, &late}, 2000, [&] { return late.countRecv(MsgType::Chat) == 1 && host.countRecv(MsgType::Chat) == 1; }));
}
#endif

static void testRoomFull() {
    std::printf("[oda dolu]\n");
    Node host;
    std::string err;
    CHECK(host.s.host(0, "Host", err));
    uint16_t port = host.s.port();
    std::vector<std::unique_ptr<Node>> guests;
    for (size_t i = 0; i < kMaxPeers; i++) {
        guests.push_back(std::make_unique<Node>());
        guests.back()->s.join("127.0.0.1", port, "G" + std::to_string(i));
    }
    std::vector<Node*> all = {&host};
    for (auto& g : guests) all.push_back(g.get());
    CHECK(pumpUntil(all, 8000, [&] {
        size_t ok = 0;
        for (auto& g : guests) ok += g->count(Event::Kind::Connected);
        return ok == kMaxPeers;
    }));
    Node extra;
    extra.s.join("127.0.0.1", port, "Fazla");
    all.push_back(&extra);
    CHECK(pumpUntil(all, 4000, [&] { return extra.count(Event::Kind::Error) == 1; }));
    const Event* e = extra.find(Event::Kind::Error);
    CHECK(e && e->text.find("Room is full") != std::string::npos);
    // kalabalikta imlec yayini
    guests[0]->s.send(MsgType::Cursor, encodeCursor({1, 2, 0}));
    CHECK(pumpUntil(all, 3000, [&] {
        size_t got = 0;
        for (size_t i = 1; i < guests.size(); i++) got += guests[i]->countRecv(MsgType::Cursor);
        return got == kMaxPeers - 1 && host.countRecv(MsgType::Cursor) == 1;
    }));
}

static void testCursorFlood() {
    std::printf("[imlec seli]\n");
    Node host, a;
    std::string err;
    CHECK(host.s.host(0, "Host", err));
    a.s.join("127.0.0.1", host.s.port(), "A");
    CHECK(pumpUntil({&host, &a}, 3000, [&] { return a.count(Event::Kind::Connected) == 1; }));
    for (int i = 1; i <= 20000; i++) a.s.send(MsgType::Cursor, encodeCursor({(float)i, 0, 0}));
    pumpUntil({&host, &a}, 5000, [&] { return host.countRecv(MsgType::Cursor) >= 20000; });
    size_t got = host.countRecv(MsgType::Cursor);
    std::printf("  host %zu / 20000 imlec paketi aldi\n", got);
    CHECK(got > 1000);
    float last = 0;
    bool mono = true;
    for (auto& e : host.log) {
        if (e.kind == Event::Kind::Received && e.msg.type == MsgType::Cursor) {
            CursorState c;
            decodeCursor(e.msg.payload, c);
            if (c.x < last) mono = false;
            last = c.x;
        }
    }
    CHECK(mono);
}

int main() {
    testCodec();
    testParseAddress();
    testClassify();
    testSession();
    testConnectFail();
#ifndef _WIN32
    testHostile();
#endif
    testRoomFull();
    testCursorFlood();
    std::printf("\n%d gecti, %d basarisiz\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
