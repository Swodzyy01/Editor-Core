// net_core.cpp - bkz. net_core.hpp
#include "net_core.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t = SOCKET;
using PollFd = WSAPOLLFD;
static constexpr sock_t kBadSock = INVALID_SOCKET;
static int sockErr() { return WSAGetLastError(); }
static bool errWouldBlock(int e) { return e == WSAEWOULDBLOCK; }
static bool errInProgress(int e) { return e == WSAEWOULDBLOCK; }
static bool errInterrupted(int e) { return e == WSAEINTR; }
static void closeSock(sock_t s) { closesocket(s); }
static int pollFds(PollFd* f, size_t n, int ms) { return WSAPoll(f, (ULONG)n, ms); }
static bool setNonBlocking(sock_t s) { u_long on = 1; return ioctlsocket(s, FIONBIO, &on) == 0; }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using sock_t = int;
using PollFd = struct pollfd;
static constexpr sock_t kBadSock = -1;
static int sockErr() { return errno; }
static bool errWouldBlock(int e) { return e == EAGAIN || e == EWOULDBLOCK; }
static bool errInProgress(int e) { return e == EINPROGRESS; }
static bool errInterrupted(int e) { return e == EINTR; }
static void closeSock(sock_t s) { ::close(s); }
static int pollFds(PollFd* f, size_t n, int ms) { return ::poll(f, (nfds_t)n, ms); }
static bool setNonBlocking(sock_t s) {
    int fl = fcntl(s, F_GETFL, 0);
    return fl >= 0 && fcntl(s, F_SETFL, fl | O_NONBLOCK) == 0;
}
#endif

namespace collab {

// ============================================================ Writer / Reader

Writer& Writer::u8(uint8_t v) { buf_.push_back(v); return *this; }
Writer& Writer::u16(uint16_t v) {
    buf_.push_back((uint8_t)(v & 0xFF));
    buf_.push_back((uint8_t)(v >> 8));
    return *this;
}
Writer& Writer::u32(uint32_t v) {
    for (int i = 0; i < 4; i++) buf_.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
    return *this;
}
Writer& Writer::i32(int32_t v) { return u32((uint32_t)v); }
Writer& Writer::u64(uint64_t v) {
    for (int i = 0; i < 8; i++) buf_.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
    return *this;
}
Writer& Writer::f32(float v) {
    uint32_t b;
    std::memcpy(&b, &v, 4);
    return u32(b);
}
Writer& Writer::str(const std::string& s) {
    size_t n = std::min<size_t>(s.size(), 65535);
    u16((uint16_t)n);
    buf_.insert(buf_.end(), s.begin(), s.begin() + n);
    return *this;
}
Writer& Writer::bytes(const std::vector<uint8_t>& b) {
    u32((uint32_t)b.size());
    buf_.insert(buf_.end(), b.begin(), b.end());
    return *this;
}

bool Reader::need(size_t n) {
    if (!ok_ || d_.size() - pos_ < n) { ok_ = false; return false; }
    return true;
}
uint8_t Reader::u8() { return need(1) ? d_[pos_++] : 0; }
uint16_t Reader::u16() {
    if (!need(2)) return 0;
    uint16_t v = (uint16_t)(d_[pos_] | (d_[pos_ + 1] << 8));
    pos_ += 2;
    return v;
}
uint32_t Reader::u32() {
    if (!need(4)) return 0;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)d_[pos_ + i] << (8 * i);
    pos_ += 4;
    return v;
}
int32_t Reader::i32() { return (int32_t)u32(); }
uint64_t Reader::u64() {
    if (!need(8)) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)d_[pos_ + i] << (8 * i);
    pos_ += 8;
    return v;
}
float Reader::f32() {
    uint32_t b = u32();
    float v;
    std::memcpy(&v, &b, 4);
    return v;
}
std::string Reader::str() {
    uint16_t n = u16();
    if (!need(n)) return {};
    std::string s((const char*)d_.data() + pos_, n);
    pos_ += n;
    return s;
}
std::vector<uint8_t> Reader::bytes() {
    uint32_t n = u32();
    if (!need(n)) return {};
    std::vector<uint8_t> v(d_.begin() + pos_, d_.begin() + pos_ + n);
    pos_ += n;
    return v;
}

std::vector<uint8_t> encodeCursor(const CursorState& c) {
    Writer w;
    w.f32(c.x).f32(c.y).u8(c.flags);
    return w.take();
}
bool decodeCursor(const std::vector<uint8_t>& payload, CursorState& out) {
    Reader r(payload);
    out.x = r.f32();
    out.y = r.f32();
    out.flags = r.u8();
    return r.ok();
}

bool parseAddress(const std::string& textIn, std::string& host, uint16_t& port, uint16_t defPort) {
    std::string t = textIn;
    while (!t.empty() && (t.back() == ' ' || t.back() == '\t' || t.back() == '\r' || t.back() == '\n')) t.pop_back();
    size_t s = 0;
    while (s < t.size() && (t[s] == ' ' || t[s] == '\t')) s++;
    t = t.substr(s);
    if (t.empty()) return false;

    std::string h = t;
    uint16_t p = defPort;
    size_t colon = t.rfind(':');
    if (colon != std::string::npos) {
        h = t.substr(0, colon);
        std::string ps = t.substr(colon + 1);
        if (ps.empty() || ps.size() > 5) return false;
        unsigned long v = 0;
        for (char ch : ps) {
            if (ch < '0' || ch > '9') return false;
            v = v * 10 + (unsigned long)(ch - '0');
        }
        if (v == 0 || v > 65535) return false;
        p = (uint16_t)v;
    }
    if (h.empty() || h.size() > 253) return false;
    for (char ch : h) {
        bool okc = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '.' || ch == '-';
        if (!okc) return false; // IPv6 ve diger garip seyleri reddet
    }
    host = h;
    port = p;
    return true;
}

// ============================================================ yardimcilar

namespace {

using Clock = std::chrono::steady_clock;
int64_t nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
}

void wsaInit() {
#ifdef _WIN32
    static WSADATA d;
    static bool ok = (WSAStartup(MAKEWORD(2, 2), &d) == 0);
    (void)ok;
#endif
}

void putU32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; i++) v.push_back((uint8_t)((x >> (8 * i)) & 0xFF));
}
uint32_t getU32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

std::vector<uint8_t> buildFrame(MsgType t, uint32_t from, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> f;
    uint32_t len = (uint32_t)(1 + 4 + payload.size());
    f.reserve(4 + (size_t)len);
    putU32(f, len);
    f.push_back((uint8_t)t);
    putU32(f, from);
    f.insert(f.end(), payload.begin(), payload.end());
    return f;
}

// Isim temizle: kontrol karakterlerini at, kirp, 32 bayta kes (UTF-8'i ortadan bolme)
std::string sanitizeName(std::string n) {
    std::string out;
    for (unsigned char ch : n)
        if (ch >= 0x20 && ch != 0x7F) out.push_back((char)ch);
    size_t a = 0;
    while (a < out.size() && out[a] == ' ') a++;
    size_t b = out.size();
    while (b > a && out[b - 1] == ' ') b--;
    out = out.substr(a, b - a);
    if (out.size() > 32) {
        size_t cut = 32;
        while (cut > 0 && (((unsigned char)out[cut]) & 0xC0) == 0x80) cut--;
        out = out.substr(0, cut);
    }
    return out;
}

constexpr size_t kMaxOutBuf = 256u * 1024u * 1024u; // yavas istemci cok birikirse at
constexpr size_t kCursorDropBacklog = 256u * 1024u; // backlog bunu asarsa imlec paketlerini atla
constexpr size_t kPreHandshakeMaxFrame = 4096;
constexpr int64_t kHandshakeTimeoutMs = 8000;
constexpr int64_t kIdleTimeoutMs = 10000;
constexpr int64_t kPingEveryMs = 2000;
constexpr size_t kMaxEvents = 100000;

} // namespace

// ============================================================ Session::Impl

struct Session::Impl {
    struct Conn {
        sock_t fd = kBadSock;
        uint32_t id = 0;
        std::string name;
        bool handshaken = false;
        std::vector<uint8_t> in;
        size_t inOff = 0;
        std::vector<uint8_t> out;
        size_t outOff = 0;
        int64_t created = 0, lastRecv = 0, lastPing = 0;
        int rtt = -1;
        bool dead = false;
        bool closeAfterFlush = false;
        std::string deadReason;
    };

    struct Cmd {
        enum Kind { SendAll, SendTo, Kick } kind{};
        uint32_t peer = 0;
        MsgType type{};
        std::vector<uint8_t> payload;
        std::string text;
    };

    // ortak durum
    std::atomic<bool> running{false};
    std::atomic<bool> stopFlag{false};
    std::atomic<bool> hostRole{false};
    std::atomic<uint32_t> myId{0};
    std::atomic<uint16_t> boundPort{0};
    std::thread th;

    std::mutex cmdMx;
    std::deque<Cmd> cmds;
    mutable std::mutex evMx;
    std::deque<Event> events;
    mutable std::mutex peerMx;
    std::map<uint32_t, PeerInfo> peerMap;

    // sadece I/O thread
    std::string myName;
    sock_t listenFd = kBadSock;
    std::vector<std::unique_ptr<Conn>> conns;
    uint32_t nextId = 2;
    std::string joinAddr;
    uint16_t joinPort = 0;

    // ------------------------------------------------ olaylar / peer listesi
    void pushEvent(Event e) {
        std::lock_guard<std::mutex> lk(evMx);
        if (events.size() >= kMaxEvents && e.kind == Event::Kind::Received && e.msg.type == MsgType::Cursor) return;
        events.push_back(std::move(e));
    }
    void pushSimple(Event::Kind k, uint32_t id, std::string text) {
        Event e;
        e.kind = k;
        e.peerId = id;
        e.text = std::move(text);
        pushEvent(std::move(e));
    }
    void setPeer(uint32_t id, const std::string& name, bool isHost) {
        std::lock_guard<std::mutex> lk(peerMx);
        PeerInfo& p = peerMap[id];
        p.id = id;
        p.name = name;
        p.isHost = isHost;
    }
    void setRtt(uint32_t id, int rtt) {
        std::lock_guard<std::mutex> lk(peerMx);
        auto it = peerMap.find(id);
        if (it != peerMap.end()) it->second.rttMs = rtt;
    }
    std::string removePeer(uint32_t id) {
        std::lock_guard<std::mutex> lk(peerMx);
        auto it = peerMap.find(id);
        if (it == peerMap.end()) return {};
        std::string n = it->second.name;
        peerMap.erase(it);
        return n;
    }

    // ------------------------------------------------ baglanti islemleri
    void kill(Conn& c, const std::string& reason) {
        if (c.dead) return;
        c.dead = true;
        if (c.deadReason.empty()) c.deadReason = reason;
    }

    void enqueue(Conn& c, const std::vector<uint8_t>& frame, bool droppable = false) {
        if (c.dead) return;
        size_t backlog = c.out.size() - c.outOff;
        if (droppable && backlog > kCursorDropBacklog) return;
        if (backlog + frame.size() > kMaxOutBuf) {
            kill(c, "send buffer overflow (peer too slow)");
            return;
        }
        if (c.outOff == c.out.size()) {
            c.out.clear();
            c.outOff = 0;
        }
        c.out.insert(c.out.end(), frame.begin(), frame.end());
    }

    void flush(Conn& c) {
        while (!c.dead && c.outOff < c.out.size()) {
            size_t want = c.out.size() - c.outOff;
            int flags = 0;
#ifdef MSG_NOSIGNAL
            flags |= MSG_NOSIGNAL;
#endif
            auto n = ::send(c.fd, (const char*)c.out.data() + c.outOff, (int)std::min<size_t>(want, 1u << 20), flags);
            if (n > 0) {
                c.outOff += (size_t)n;
            } else {
                int e = sockErr();
                if (n < 0 && errWouldBlock(e)) break;
                if (n < 0 && errInterrupted(e)) continue;
                kill(c, "send failed");
                return;
            }
        }
        if (c.outOff >= c.out.size()) {
            c.out.clear();
            c.outOff = 0;
            if (c.closeAfterFlush) kill(c, c.deadReason.empty() ? "closed" : c.deadReason);
        }
    }

    Conn* findConn(uint32_t id) {
        for (auto& c : conns)
            if (c->handshaken && c->id == id && !c->dead) return c.get();
        return nullptr;
    }

    void broadcast(const std::vector<uint8_t>& frame, uint32_t exceptId, bool droppable) {
        for (auto& c : conns)
            if (c->handshaken && !c->dead && c->id != exceptId) enqueue(*c, frame, droppable);
    }

    // ------------------------------------------------ gelen paket isleme
    void onFrame(Conn& c, MsgType type, uint32_t from, std::vector<uint8_t>&& payload) {
        c.lastRecv = nowMs();
        if (hostRole) hostOnFrame(c, type, std::move(payload));
        else clientOnFrame(c, type, from, std::move(payload));
    }

    void hostHello(Conn& c, const std::vector<uint8_t>& payload) {
        Reader r(payload);
        uint16_t ver = r.u16();
        std::string nm = r.str();
        if (!r.ok()) {
            kill(c, "bad Hello");
            return;
        }
        auto refuse = [&](const std::string& why) {
            Writer w;
            w.str(why);
            enqueue(c, buildFrame(MsgType::Kick, kHostId, w.data()));
            c.closeAfterFlush = true;
            c.deadReason = why;
        };
        if (ver != kProtocolVersion) {
            refuse("Version mismatch: host uses protocol v" + std::to_string(kProtocolVersion) + ", you use v" + std::to_string(ver));
            return;
        }
        size_t count = 0;
        for (auto& o : conns)
            if (o->handshaken && !o->dead) count++;
        if (count >= kMaxPeers) {
            refuse("Room is full");
            return;
        }
        c.id = nextId++;
        c.name = sanitizeName(nm);
        if (c.name.empty()) c.name = "Player" + std::to_string(c.id);

        // Welcome: sana verilen id + odada kimler var (host dahil, sen haric)
        Writer w;
        w.u32(c.id);
        std::vector<std::pair<uint32_t, std::string>> roster;
        roster.emplace_back(kHostId, myName);
        for (auto& o : conns)
            if (o->handshaken && !o->dead && o.get() != &c) roster.emplace_back(o->id, o->name);
        w.u32((uint32_t)roster.size());
        for (auto& pr : roster) w.u32(pr.first).str(pr.second);
        enqueue(c, buildFrame(MsgType::Welcome, kHostId, w.data()));

        // digerlerine "biri girdi" de
        Writer j;
        j.u32(c.id).str(c.name);
        broadcast(buildFrame(MsgType::PeerJoined, kHostId, j.data()), c.id, false);

        c.handshaken = true; // broadcast'ten SONRA, kendine PeerJoined gitmesin
        setPeer(c.id, c.name, false);
        pushSimple(Event::Kind::PeerJoined, c.id, c.name);
    }

    void hostOnFrame(Conn& c, MsgType type, std::vector<uint8_t>&& payload) {
        if (!c.handshaken) {
            if (type != MsgType::Hello) {
                kill(c, "expected Hello");
                return;
            }
            hostHello(c, payload);
            return;
        }
        switch (type) {
            case MsgType::Ping:
                enqueue(c, buildFrame(MsgType::Pong, kHostId, payload));
                break;
            case MsgType::Pong: {
                Reader r(payload);
                uint64_t ts = r.u64();
                if (r.ok()) {
                    int64_t d = nowMs() - (int64_t)ts;
                    c.rtt = (int)std::max<int64_t>(0, std::min<int64_t>(d, 60000));
                    setRtt(c.id, c.rtt);
                }
                break;
            }
            case MsgType::Cursor:
            case MsgType::Op:
            case MsgType::Chat: {
                // digerlerine role et (gonderen haric), kendimize de teslim et
                broadcast(buildFrame(type, c.id, payload), c.id, type == MsgType::Cursor);
                Event e;
                e.kind = Event::Kind::Received;
                e.peerId = c.id;
                e.msg.type = type;
                e.msg.from = c.id;
                e.msg.payload = std::move(payload);
                pushEvent(std::move(e));
                break;
            }
            case MsgType::LevelData: {
                Event e;
                e.kind = Event::Kind::Received;
                e.peerId = c.id;
                e.msg.type = type;
                e.msg.from = c.id;
                e.msg.payload = std::move(payload);
                pushEvent(std::move(e));
                break;
            }
            default:
                break; // Hello tekrari, Welcome/PeerJoined/PeerLeft/Kick sahteciligi vs: yok say
        }
    }

    void clientOnFrame(Conn& c, MsgType type, uint32_t from, std::vector<uint8_t>&& payload) {
        switch (type) {
            case MsgType::Welcome: {
                if (c.handshaken) break;
                Reader r(payload);
                uint32_t id = r.u32();
                uint32_t n = r.u32();
                std::vector<std::pair<uint32_t, std::string>> roster;
                for (uint32_t i = 0; i < n && r.ok() && i <= kMaxPeers + 1; i++) {
                    uint32_t pid = r.u32();
                    std::string nm = r.str();
                    roster.emplace_back(pid, nm);
                }
                if (!r.ok() || id == 0) {
                    kill(c, "bad Welcome");
                    return;
                }
                c.handshaken = true;
                c.id = kHostId;
                myId = id;
                setPeer(id, myName, false);
                for (auto& pr : roster) setPeer(pr.first, pr.second, pr.first == kHostId);
                pushSimple(Event::Kind::Connected, id, "");
                for (auto& pr : roster) pushSimple(Event::Kind::PeerJoined, pr.first, pr.second);
                break;
            }
            case MsgType::PeerJoined: {
                if (!c.handshaken) break;
                Reader r(payload);
                uint32_t id = r.u32();
                std::string nm = r.str();
                if (!r.ok()) break;
                setPeer(id, nm, false);
                pushSimple(Event::Kind::PeerJoined, id, nm);
                break;
            }
            case MsgType::PeerLeft: {
                if (!c.handshaken) break;
                Reader r(payload);
                uint32_t id = r.u32();
                if (!r.ok()) break;
                std::string nm = removePeer(id);
                pushSimple(Event::Kind::PeerLeft, id, nm);
                break;
            }
            case MsgType::Kick: {
                Reader r(payload);
                std::string why = r.str();
                if (why.empty()) why = "Kicked by host";
                kill(c, why);
                break;
            }
            case MsgType::Ping:
                enqueue(c, buildFrame(MsgType::Pong, 0, payload));
                break;
            case MsgType::Pong: {
                Reader r(payload);
                uint64_t ts = r.u64();
                if (r.ok()) {
                    int64_t d = nowMs() - (int64_t)ts;
                    c.rtt = (int)std::max<int64_t>(0, std::min<int64_t>(d, 60000));
                    setRtt(kHostId, c.rtt);
                }
                break;
            }
            case MsgType::Cursor:
            case MsgType::Op:
            case MsgType::Chat:
            case MsgType::LevelData: {
                if (!c.handshaken) break;
                Event e;
                e.kind = Event::Kind::Received;
                e.peerId = from;
                e.msg.type = type;
                e.msg.from = from;
                e.msg.payload = std::move(payload);
                pushEvent(std::move(e));
                break;
            }
            default:
                break;
        }
    }

    void parseFrames(Conn& c) {
        while (!c.dead) {
            size_t avail = c.in.size() - c.inOff;
            if (avail < 4) break;
            uint32_t len = getU32(c.in.data() + c.inOff);
            if (len < 5 || len > kMaxFrame) {
                kill(c, "protocol error (bad frame size)");
                return;
            }
            if (hostRole && !c.handshaken && len > kPreHandshakeMaxFrame) {
                kill(c, "protocol error (oversized pre-handshake frame)");
                return;
            }
            if (avail < 4 + (size_t)len) break; // paketin geri kalani henuz gelmedi
            const uint8_t* p = c.in.data() + c.inOff + 4;
            MsgType type = (MsgType)p[0];
            uint32_t from = getU32(p + 1);
            std::vector<uint8_t> payload(p + 5, p + len);
            c.inOff += 4 + (size_t)len;
            onFrame(c, type, from, std::move(payload));
        }
        if (c.inOff == c.in.size()) {
            c.in.clear();
            c.inOff = 0;
        } else if (c.inOff > (1u << 20)) {
            c.in.erase(c.in.begin(), c.in.begin() + (long)c.inOff);
            c.inOff = 0;
        }
    }

    void readConn(Conn& c) {
        uint8_t buf[65536];
        for (int round = 0; round < 64 && !c.dead; round++) {
            auto n = ::recv(c.fd, (char*)buf, (int)sizeof(buf), 0);
            if (n > 0) {
                c.in.insert(c.in.end(), buf, buf + n);
                parseFrames(c);
            } else if (n == 0) {
                kill(c, c.handshaken ? "connection closed" : "connection closed before handshake");
                return;
            } else {
                int e = sockErr();
                if (errWouldBlock(e)) return;
                if (errInterrupted(e)) continue;
                kill(c, "connection lost");
                return;
            }
        }
    }

    // ------------------------------------------------ komutlar (ana thread -> I/O thread)
    void processCmds() {
        std::deque<Cmd> local;
        {
            std::lock_guard<std::mutex> lk(cmdMx);
            local.swap(cmds);
        }
        for (auto& cmd : local) {
            switch (cmd.kind) {
                case Cmd::SendAll: {
                    if (hostRole) {
                        broadcast(buildFrame(cmd.type, kHostId, cmd.payload), 0, cmd.type == MsgType::Cursor);
                    } else {
                        for (auto& c : conns)
                            if (c->handshaken && !c->dead) enqueue(*c, buildFrame(cmd.type, 0, cmd.payload), cmd.type == MsgType::Cursor);
                    }
                    break;
                }
                case Cmd::SendTo: {
                    if (!hostRole) break;
                    if (Conn* c = findConn(cmd.peer)) enqueue(*c, buildFrame(cmd.type, kHostId, cmd.payload), cmd.type == MsgType::Cursor);
                    break;
                }
                case Cmd::Kick: {
                    if (!hostRole) break;
                    if (Conn* c = findConn(cmd.peer)) {
                        Writer w;
                        w.str(cmd.text);
                        enqueue(*c, buildFrame(MsgType::Kick, kHostId, w.data()));
                        c->closeAfterFlush = true;
                        c->deadReason = cmd.text.empty() ? "Kicked by host" : cmd.text;
                    }
                    break;
                }
            }
        }
    }

    // ------------------------------------------------ kapananlari temizle
    void reapDead() {
        for (size_t i = 0; i < conns.size();) {
            Conn& c = *conns[i];
            if (!c.dead) {
                i++;
                continue;
            }
            if (c.fd != kBadSock) closeSock(c.fd);
            c.fd = kBadSock;
            if (hostRole) {
                if (c.handshaken) {
                    std::string nm = removePeer(c.id);
                    Writer w;
                    w.u32(c.id);
                    broadcast(buildFrame(MsgType::PeerLeft, kHostId, w.data()), c.id, false);
                    pushSimple(Event::Kind::PeerLeft, c.id, nm);
                }
            } else {
                // Istemci icin tek baglanti = oturum. running'i olaydan ONCE kapat ki
                // Disconnected'i okuyan kod running()==false gorsun.
                stopFlag = true;
                running = false;
                if (c.handshaken) pushSimple(Event::Kind::Disconnected, myId.load(), c.deadReason);
                else pushSimple(Event::Kind::Error, 0, c.deadReason);
            }
            conns.erase(conns.begin() + (long)i);
        }
    }

    void housekeeping() {
        int64_t now = nowMs();
        for (auto& cp : conns) {
            Conn& c = *cp;
            if (c.dead) continue;
            if (!c.handshaken && now - c.created > kHandshakeTimeoutMs) {
                kill(c, "handshake timeout");
                continue;
            }
            if (c.handshaken && now - c.lastRecv > kIdleTimeoutMs) {
                kill(c, "timed out");
                continue;
            }
            if (c.handshaken && now - c.lastPing >= kPingEveryMs) {
                c.lastPing = now;
                Writer w;
                w.u64((uint64_t)now);
                enqueue(c, buildFrame(MsgType::Ping, hostRole ? kHostId : 0, w.data()));
            }
        }
    }

    void acceptAll() {
        for (int i = 0; i < 64; i++) {
            sockaddr_in sa;
            socklen_t sl = sizeof(sa);
            sock_t fd = ::accept(listenFd, (sockaddr*)&sa, &sl);
            if (fd == kBadSock) return;
            setNonBlocking(fd);
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
#ifdef SO_NOSIGPIPE
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (const char*)&one, sizeof(one));
#endif
            auto c = std::make_unique<Conn>();
            c->fd = fd;
            c->created = c->lastRecv = c->lastPing = nowMs();
            conns.push_back(std::move(c));
        }
    }

    // ------------------------------------------------ istemci baglantisi (I/O thread icinde)
    bool clientConnect(std::string& err) {
        addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(joinAddr.c_str(), std::to_string(joinPort).c_str(), &hints, &res) != 0 || !res) {
            err = "Cannot resolve address: " + joinAddr;
            return false;
        }
        sock_t fd = kBadSock;
        std::string lastErr = "connection failed";
        for (addrinfo* ai = res; ai && fd == kBadSock; ai = ai->ai_next) {
            sock_t s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s == kBadSock) continue;
            setNonBlocking(s);
            int rc = ::connect(s, ai->ai_addr, (int)ai->ai_addrlen);
            bool ok = (rc == 0);
            if (!ok && errInProgress(sockErr())) {
                int64_t deadline = nowMs() + 6000;
                while (!stopFlag && nowMs() < deadline) {
                    PollFd p;
                    std::memset(&p, 0, sizeof(p));
                    p.fd = s;
                    p.events = POLLOUT;
                    int pr = pollFds(&p, 1, 50);
                    if (pr > 0) {
                        int soerr = 0;
                        socklen_t sl = sizeof(soerr);
                        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soerr, &sl);
                        if (soerr == 0 && (p.revents & POLLOUT)) ok = true;
                        else lastErr = "connection refused or unreachable";
                        break;
                    }
                }
                if (!ok && lastErr == "connection failed") lastErr = "connection timed out";
            }
            if (ok) fd = s;
            else closeSock(s);
        }
        freeaddrinfo(res);
        if (fd == kBadSock) {
            err = lastErr;
            return false;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
#ifdef SO_NOSIGPIPE
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (const char*)&one, sizeof(one));
#endif
        auto c = std::make_unique<Conn>();
        c->fd = fd;
        c->created = c->lastRecv = c->lastPing = nowMs();
        Writer w;
        w.u16(kProtocolVersion).str(myName);
        enqueue(*c, buildFrame(MsgType::Hello, 0, w.data()));
        conns.push_back(std::move(c));
        return true;
    }

    // ------------------------------------------------ ana dongu
    void loop() {
        while (!stopFlag) {
            processCmds();

            std::vector<PollFd> fds;
            fds.reserve(conns.size() + 1);
            size_t nConns = conns.size();
            if (hostRole) {
                PollFd p;
                std::memset(&p, 0, sizeof(p));
                p.fd = listenFd;
                p.events = POLLIN;
                fds.push_back(p);
            }
            for (size_t i = 0; i < nConns; i++) {
                PollFd p;
                std::memset(&p, 0, sizeof(p));
                p.fd = conns[i]->fd;
                p.events = POLLIN;
                if (conns[i]->outOff < conns[i]->out.size()) p.events |= POLLOUT;
                fds.push_back(p);
            }

            if (fds.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            } else {
                int r = pollFds(fds.data(), fds.size(), 5);
                if (r < 0) {
                    int e = sockErr();
                    if (!errInterrupted(e)) std::this_thread::sleep_for(std::chrono::milliseconds(5));
                } else if (r > 0) {
                    size_t idx = 0;
                    if (hostRole) {
                        if (fds[0].revents & POLLIN) acceptAll();
                        idx = 1;
                    }
                    for (size_t i = 0; i < nConns; i++) {
                        Conn& c = *conns[i];
                        short rev = fds[idx + i].revents;
                        if (rev & (POLLERR | POLLNVAL)) {
                            kill(c, "socket error");
                            continue;
                        }
                        if (rev & (POLLIN | POLLHUP)) readConn(c);
                    }
                }
            }

            // Komutlarin ve paketlerin urettigi cevaplari beklemeden yolla (dusuk gecikme)
            processCmds();
            housekeeping();
            for (auto& c : conns)
                if (!c->dead) flush(*c);
            reapDead();
        }

        // kapanis
        for (auto& c : conns)
            if (c->fd != kBadSock) closeSock(c->fd);
        conns.clear();
        if (listenFd != kBadSock) {
            closeSock(listenFd);
            listenFd = kBadSock;
        }
        running = false;
    }

    void threadMain(bool asHost) {
        if (!asHost) {
            std::string err;
            if (!clientConnect(err)) {
                running = false; // olaydan once (bkz. reapDead)
                pushSimple(Event::Kind::Error, 0, "Could not connect to " + joinAddr + ":" + std::to_string(joinPort) + " (" + err + ")");
                return;
            }
        }
        loop();
    }
};

// ============================================================ Session

Session::Session() : m_(new Impl()) {}
Session::~Session() { stop(); }

bool Session::host(uint16_t port, const std::string& playerName, std::string& err) {
    stop();
    wsaInit();
    Impl& m = *m_;
    m.stopFlag = false;
    m.hostRole = true;
    m.myName = sanitizeName(playerName);
    if (m.myName.empty()) m.myName = "Host";
    m.nextId = 2;
    m.myId = kHostId;

    sock_t fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd == kBadSock) {
        err = "Could not create socket";
        return false;
    }
#ifndef _WIN32
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one)); // hizli yeniden acilis
#endif
    sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);
    if (::bind(fd, (sockaddr*)&sa, sizeof(sa)) != 0) {
        err = "Port " + std::to_string(port) + " is already in use or blocked";
        closeSock(fd);
        return false;
    }
    if (::listen(fd, 16) != 0) {
        err = "listen() failed";
        closeSock(fd);
        return false;
    }
    setNonBlocking(fd);
    socklen_t sl = sizeof(sa);
    getsockname(fd, (sockaddr*)&sa, &sl);
    m.boundPort = ntohs(sa.sin_port);
    m.listenFd = fd;

    {
        std::lock_guard<std::mutex> lk(m.peerMx);
        m.peerMap.clear();
    }
    m.setPeer(kHostId, m.myName, true);
    {
        std::lock_guard<std::mutex> lk(m.evMx);
        m.events.clear();
    }
    m.running = true;
    m.th = std::thread([this] { m_->threadMain(true); });
    return true;
}

void Session::join(const std::string& address, uint16_t port, const std::string& playerName) {
    stop();
    wsaInit();
    Impl& m = *m_;
    m.stopFlag = false;
    m.hostRole = false;
    m.myName = sanitizeName(playerName);
    if (m.myName.empty()) m.myName = "Player";
    m.joinAddr = address;
    m.joinPort = port;
    m.myId = 0;
    m.boundPort = 0;
    {
        std::lock_guard<std::mutex> lk(m.peerMx);
        m.peerMap.clear();
    }
    {
        std::lock_guard<std::mutex> lk(m.evMx);
        m.events.clear();
    }
    m.running = true;
    m.th = std::thread([this] { m_->threadMain(false); });
}

void Session::stop() {
    Impl& m = *m_;
    m.stopFlag = true;
    if (m.th.joinable()) m.th.join();
    m.running = false;
    {
        std::lock_guard<std::mutex> lk(m.cmdMx);
        m.cmds.clear();
    }
    {
        std::lock_guard<std::mutex> lk(m.peerMx);
        m.peerMap.clear();
    }
    m.myId = 0;
}

bool Session::running() const { return m_->running.load(); }
bool Session::isHost() const { return m_->hostRole.load(); }
uint32_t Session::myId() const { return m_->myId.load(); }
uint16_t Session::port() const { return m_->boundPort.load(); }

void Session::send(MsgType type, std::vector<uint8_t> payload) {
    Impl& m = *m_;
    if (!m.running || payload.size() + 5 > kMaxFrame) return;
    Impl::Cmd c;
    c.kind = Impl::Cmd::SendAll;
    c.type = type;
    c.payload = std::move(payload);
    std::lock_guard<std::mutex> lk(m.cmdMx);
    m.cmds.push_back(std::move(c));
}

void Session::sendTo(uint32_t peerId, MsgType type, std::vector<uint8_t> payload) {
    Impl& m = *m_;
    if (!m.running || !m.hostRole || payload.size() + 5 > kMaxFrame) return;
    Impl::Cmd c;
    c.kind = Impl::Cmd::SendTo;
    c.peer = peerId;
    c.type = type;
    c.payload = std::move(payload);
    std::lock_guard<std::mutex> lk(m.cmdMx);
    m.cmds.push_back(std::move(c));
}

void Session::kick(uint32_t peerId, const std::string& reason) {
    Impl& m = *m_;
    if (!m.running || !m.hostRole) return;
    Impl::Cmd c;
    c.kind = Impl::Cmd::Kick;
    c.peer = peerId;
    c.text = reason;
    std::lock_guard<std::mutex> lk(m.cmdMx);
    m.cmds.push_back(std::move(c));
}

bool Session::poll(Event& out) {
    std::lock_guard<std::mutex> lk(m_->evMx);
    if (m_->events.empty()) return false;
    out = std::move(m_->events.front());
    m_->events.pop_front();
    return true;
}

std::vector<PeerInfo> Session::peers() const {
    std::lock_guard<std::mutex> lk(m_->peerMx);
    std::vector<PeerInfo> v;
    v.reserve(m_->peerMap.size());
    for (auto& kv : m_->peerMap) v.push_back(kv.second);
    return v;
}

} // namespace collab
