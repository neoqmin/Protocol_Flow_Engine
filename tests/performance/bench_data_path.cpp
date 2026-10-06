// Data-path micro benchmark (A4 baseline): DataPath::seal + open round trips per packet size, single thread.
// Not a pass/fail test: prints packets/s and MB/s. Run: build/tests/pf_bench_data_path
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

#include "pf/crypto/openssl_aes_gcm.h"
#include "pf/data_path.h"

using namespace pf;

int main() {
    KeyStore tx_keys, rx_keys;
    auto aead = make_openssl_aes256gcm();
    DataKey k;
    k.key.fill(0x42);
    k.nonce_tail.fill(0x24);
    tx_keys.bind_tx(1, tx_keys.add(k));
    rx_keys.bind_rx(1, rx_keys.add(k));
    DataPath tx, rx;
    if (!tx.init(&tx_keys, aead.get()) || !rx.init(&rx_keys, aead.get())) { std::fprintf(stderr, "init failed\n"); return 1; }

    std::printf("%8s %14s %12s %12s\n", "size", "seal+open pps", "MB/s", "ns/packet");
    for (const size_t size : {64u, 256u, 512u, 1024u, 1400u}) {
        std::vector<uint8_t> plain(size, 0x45);
        const auto t0 = std::chrono::steady_clock::now();
        size_t n = 0;
        double secs = 0;
        do {
            for (int i = 0; i < 20000; ++i) {
                PacketBuffer p = DataPath::make_tx_buffer(2048);
                uint8_t* room = p.put(size);
                std::memcpy(room, plain.data(), size);
                if (tx.seal(p, 1, 0) != Error::None) { std::fprintf(stderr, "seal failed\n"); return 1; }
                if (rx.open(p).error != Error::None) { std::fprintf(stderr, "open failed\n"); return 1; }
                ++n;
            }
            secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        } while (secs < 1.5);
        std::printf("%8zu %14.0f %12.1f %12.0f\n", size, n / secs, n * size / secs / 1e6, secs * 1e9 / n);
    }
    return 0;
}
