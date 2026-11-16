#include <Geode/Geode.hpp>
#include "../local_ips.hpp"

using namespace geode::prelude;

$on_mod(Loaded) {
    for (auto& a : collab::listLocalAddresses()) {
        log::info("Collab IP: {} ({}) {}", a.ip, a.ifaceName, collab::kindLabel(a.kind));
    }
}
