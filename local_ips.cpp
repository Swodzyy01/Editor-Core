// local_ips.cpp - bkz. local_ips.hpp
#include "local_ips.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h> // iphlpapi.lib
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace collab {

namespace {

bool parseIpv4(const std::string& s, uint32_t& out) {
    unsigned a, b, c, d;
    char extra;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

std::string lower(std::string s) {
    for (auto& ch : s) ch = (char)std::tolower((unsigned char)ch);
    return s;
}

bool contains(const std::string& hay, const char* needle) { return hay.find(needle) != std::string::npos; }

bool startsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

int sortRank(NetKind k) {
    switch (k) {
        case NetKind::Radmin: return 0;
        case NetKind::Hamachi: return 1;
        case NetKind::Tailscale: return 2;
        case NetKind::ZeroTier: return 3;
        case NetKind::Lan: return 4;
        default: return 5;
    }
}

} // namespace

NetKind classifyAddress(const std::string& ifaceName, const std::string& ip) {
    std::string n = lower(ifaceName);

    // 1) Adaptor adi en guvenilir ipucu (ZeroTier 10.x gibi ozel araliklari da kapsar)
    if (contains(n, "radmin")) return NetKind::Radmin;
    if (contains(n, "hamachi")) return NetKind::Hamachi;
    if (contains(n, "tailscale")) return NetKind::Tailscale;
    if (contains(n, "zerotier") || (n.size() >= 4 && startsWith(n, "zt"))) return NetKind::ZeroTier;

    // 2) IP araligi
    uint32_t v;
    if (!parseIpv4(ip, v)) return NetKind::Other;
    uint32_t a = v >> 24;
    if (a == 26) return NetKind::Radmin;                       // 26.0.0.0/8
    if (a == 25) return NetKind::Hamachi;                      // 25.0.0.0/8
    if ((v & 0xFFC00000u) == 0x64400000u) return NetKind::Tailscale; // 100.64.0.0/10
    if (a == 10) return NetKind::Lan;                          // 10.0.0.0/8
    if ((v & 0xFFF00000u) == 0xAC100000u) return NetKind::Lan; // 172.16.0.0/12
    if ((v & 0xFFFF0000u) == 0xC0A80000u) return NetKind::Lan; // 192.168.0.0/16
    return NetKind::Other;
}

const char* kindLabel(NetKind k) {
    switch (k) {
        case NetKind::Radmin: return "Radmin VPN";
        case NetKind::Hamachi: return "Hamachi";
        case NetKind::Tailscale: return "Tailscale";
        case NetKind::ZeroTier: return "ZeroTier";
        case NetKind::Lan: return "LAN";
        default: return "Other";
    }
}

std::vector<LocalAddress> listLocalAddresses() {
    std::vector<LocalAddress> out;

#ifdef _WIN32
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buf(size);
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    }
    if (rc == NO_ERROR) {
        for (auto* a = (IP_ADAPTER_ADDRESSES*)buf.data(); a; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp) continue;
            if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            // FriendlyName (UTF-16) -> UTF-8
            std::string name;
            if (a->FriendlyName) {
                int n = WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, nullptr, 0, nullptr, nullptr);
                if (n > 1) {
                    name.resize((size_t)n - 1);
                    WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, &name[0], n, nullptr, nullptr);
                }
            }
            // Bazi sanal adaptorlerde sadece Description icinde marka adi olur
            std::string desc;
            if (a->Description) {
                int n = WideCharToMultiByte(CP_UTF8, 0, a->Description, -1, nullptr, 0, nullptr, nullptr);
                if (n > 1) {
                    desc.resize((size_t)n - 1);
                    WideCharToMultiByte(CP_UTF8, 0, a->Description, -1, &desc[0], n, nullptr, nullptr);
                }
            }
            for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
                if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
                char ipbuf[INET_ADDRSTRLEN] = {0};
                auto* sin = (sockaddr_in*)u->Address.lpSockaddr;
                if (!InetNtopA(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf))) continue;
                std::string ip = ipbuf;
                if (startsWith(ip, "127.") || startsWith(ip, "169.254.") || ip == "0.0.0.0") continue;
                LocalAddress la;
                la.ifaceName = name.empty() ? desc : name;
                la.ip = ip;
                la.kind = classifyAddress(name + " " + desc, ip);
                la.isVirtual = la.kind != NetKind::Lan && la.kind != NetKind::Other;
                out.push_back(la);
            }
        }
    }
#else
    ifaddrs* ifs = nullptr;
    if (getifaddrs(&ifs) == 0) {
        for (ifaddrs* p = ifs; p; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
            char ipbuf[INET_ADDRSTRLEN] = {0};
            auto* sin = (sockaddr_in*)p->ifa_addr;
            if (!inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf))) continue;
            std::string ip = ipbuf;
            if (startsWith(ip, "169.254.")) continue;
            LocalAddress la;
            la.ifaceName = p->ifa_name ? p->ifa_name : "";
            la.ip = ip;
            la.kind = classifyAddress(la.ifaceName, ip);
            la.isVirtual = la.kind != NetKind::Lan && la.kind != NetKind::Other;
            out.push_back(la);
        }
        freeifaddrs(ifs);
    }
#endif

    std::stable_sort(out.begin(), out.end(), [](const LocalAddress& x, const LocalAddress& y) {
        return sortRank(x.kind) < sortRank(y.kind);
    });
    return out;
}

std::string bestShareAddress(const std::vector<LocalAddress>& addrs) {
    for (auto& a : addrs)
        if (a.isVirtual) return a.ip;
    for (auto& a : addrs)
        if (a.kind == NetKind::Lan) return a.ip;
    return {};
}

} // namespace collab
