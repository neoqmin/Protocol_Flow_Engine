#include "pf/key_store.h"
#include "pf_test.h"

using namespace pf;

static DataKey make_key(uint8_t fill) {
    DataKey k;
    k.key.fill(fill);
    k.nonce_tail.fill(static_cast<uint8_t>(fill + 1));
    return k;
}

PF_TEST(key_store_add_returns_distinct_valid_refs) {
    KeyStore s;
    KeyRef a = s.add(make_key(1)), b = s.add(make_key(2));
    PF_CHECK(a.valid()); PF_CHECK(b.valid());
    PF_CHECK(a.id != b.id);
    PF_CHECK_EQ(s.size(), size_t(2));
}

PF_TEST(key_store_get_returns_material_and_null_for_unknown) {
    KeyStore s;
    KeyRef a = s.add(make_key(7));
    const DataKey* k = s.get(a);
    PF_REQUIRE(k != nullptr);
    PF_CHECK_EQ(k->key[0], 7);
    PF_CHECK_EQ(k->nonce_tail[0], 8);
    PF_CHECK(s.get(KeyRef{}) == nullptr);
    PF_CHECK(s.get(KeyRef{9999}) == nullptr);
}

PF_TEST(key_store_pointers_stay_valid_when_more_keys_are_added) {
    KeyStore s;
    KeyRef a = s.add(make_key(1));
    DataKey* pa = s.get(a);
    for (int i = 0; i < 100; ++i) s.add(make_key(2));
    PF_CHECK(s.get(a) == pa);
}

PF_TEST(key_store_binds_rx_and_tx_by_key_id) {
    KeyStore s;
    KeyRef rx = s.add(make_key(1)), tx = s.add(make_key(2));
    PF_CHECK(s.bind_rx(3, rx));
    PF_CHECK(s.bind_tx(3, tx));
    PF_CHECK(s.rx_for_key_id(3).id == rx.id);
    PF_CHECK(s.tx_for_key_id(3).id == tx.id);
    PF_CHECK(!s.rx_for_key_id(4).valid());
    PF_CHECK(!s.tx_for_key_id(4).valid());
}

PF_TEST(key_store_rejects_bad_bindings) {
    KeyStore s;
    KeyRef a = s.add(make_key(1));
    PF_CHECK(!s.bind_rx(8, a));                  // key_id is 3 bits
    PF_CHECK(!s.bind_rx(0, KeyRef{42}));         // unknown ref
    PF_CHECK(!s.rx_for_key_id(8).valid());
    PF_CHECK(!s.tx_for_key_id(255).valid());
}

PF_TEST(key_store_rebinding_a_key_id_replaces_the_old_key) {
    KeyStore s;
    KeyRef a = s.add(make_key(1)), b = s.add(make_key(2));
    s.bind_rx(1, a);
    s.bind_rx(1, b);
    PF_CHECK(s.rx_for_key_id(1).id == b.id);
}

PF_TEST(key_store_remove_drops_key_and_its_bindings) {
    KeyStore s;
    KeyRef a = s.add(make_key(1));
    s.bind_rx(2, a); s.bind_tx(2, a);
    s.remove(a);
    PF_CHECK(s.get(a) == nullptr);
    PF_CHECK(!s.rx_for_key_id(2).valid());
    PF_CHECK(!s.tx_for_key_id(2).valid());
    PF_CHECK_EQ(s.size(), size_t(0));
    s.remove(a);                                  // idempotent
}

PF_TEST(datakey_wipe_zeroes_all_secret_material) {
    DataKey k = make_key(0x5A);
    k.replay.commit(10);
    k.tx_next = 77;
    k.wipe();
    for (auto b : k.key) PF_CHECK_EQ(b, 0);
    for (auto b : k.nonce_tail) PF_CHECK_EQ(b, 0);
    PF_CHECK_EQ(k.replay.highest(), 0u);
    PF_CHECK_EQ(k.tx_next, 1u);
}

PF_TEST(tx_packet_ids_are_sequential_from_one) {
    DataKey k = make_key(1);
    uint32_t id = 0;
    PF_CHECK(k.next_tx_id(id)); PF_CHECK_EQ(id, 1u);
    PF_CHECK(k.next_tx_id(id)); PF_CHECK_EQ(id, 2u);
}

PF_TEST(tx_packet_ids_never_wrap_nonce_reuse_is_refused) {
    DataKey k = make_key(1);
    k.tx_next = 0xFFFFFFFFu;
    uint32_t id = 0;
    PF_CHECK(k.next_tx_id(id));
    PF_CHECK_EQ(id, 0xFFFFFFFFu);
    PF_CHECK(!k.next_tx_id(id));                  // exhausted: renegotiate, never reuse
    PF_CHECK(!k.next_tx_id(id));
}
