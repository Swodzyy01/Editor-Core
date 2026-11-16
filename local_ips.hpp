// local_ips.hpp - "Benim sanal oda IP'm ne?" icin bu bilgisayarin IPv4 adreslerini listeler
// ve Radmin / Hamachi / Tailscale / ZeroTier gibi sanal ag adresleri olarak isaretler.
#pragma once

#include <string>
#include <vector>

namespace collab {

enum class NetKind { Radmin, Hamachi, Tailscale, ZeroTier, Lan, Other };

struct LocalAddress {
    std::string ifaceName; // adaptor adi ("Radmin VPN", "eth0", ...)
    std::string ip;        // "26.12.34.56"
    NetKind kind = NetKind::Other;
    bool isVirtual = false; // Radmin/Hamachi/Tailscale/ZeroTier ise true
};

// Adaptor adina + IP araligina bakip turu tahmin eder (saf fonksiyon, test edilebilir).
NetKind classifyAddress(const std::string& ifaceName, const std::string& ip);
const char* kindLabel(NetKind k);

// Calisan, loopback/link-local olmayan IPv4'ler. Sanal ag adresleri basta gelir.
std::vector<LocalAddress> listLocalAddresses();

// Arkadaslara verilecek en iyi adres: once sanal ag, yoksa LAN, yoksa bos string.
std::string bestShareAddress(const std::vector<LocalAddress>& addrs);

} // namespace collab
