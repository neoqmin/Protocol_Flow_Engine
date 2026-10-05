#include "pf/replay.h"
#include "pf_test.h"

using namespace pf;

PF_TEST(replay_first_id_is_accepted_zero_is_invalid) {
    ReplayWindow w;
    PF_CHECK(w.check(1) == ReplayStatus::Ok);
    PF_CHECK(w.check(0) == ReplayStatus::InvalidId);   // OpenVPN packet-ids start at 1
}

PF_TEST(replay_check_does_not_mutate_state) {
    ReplayWindow w;
    PF_CHECK(w.check(5) == ReplayStatus::Ok);
    PF_CHECK(w.check(5) == ReplayStatus::Ok);          // not committed => still fresh
    PF_CHECK_EQ(w.highest(), 0u);
}

PF_TEST(replay_committed_id_is_rejected) {
    ReplayWindow w;
    w.commit(5);
    PF_CHECK(w.check(5) == ReplayStatus::Replay);
    PF_CHECK_EQ(w.highest(), 5u);
}

PF_TEST(replay_out_of_order_within_window_accepted_once) {
    ReplayWindow w;
    w.commit(10);
    PF_CHECK(w.check(7) == ReplayStatus::Ok);
    w.commit(7);
    PF_CHECK(w.check(7) == ReplayStatus::Replay);
    PF_CHECK(w.check(8) == ReplayStatus::Ok);          // other unseen ids still fine
    PF_CHECK_EQ(w.highest(), 10u);
}

PF_TEST(replay_window_boundary_is_64) {
    ReplayWindow w;
    w.commit(100);
    PF_CHECK(w.check(37) == ReplayStatus::Ok);         // 100-37 = 63 < 64
    PF_CHECK(w.check(36) == ReplayStatus::TooOld);     // 100-36 = 64
    PF_CHECK(w.check(1) == ReplayStatus::TooOld);
}

PF_TEST(replay_window_slides_and_forgets_old_bits) {
    ReplayWindow w;
    w.commit(1);
    w.commit(2);
    w.commit(70);                                      // shift by 68 >= 64 clears history
    PF_CHECK(w.check(70) == ReplayStatus::Replay);
    PF_CHECK(w.check(2) == ReplayStatus::TooOld);
    PF_CHECK(w.check(69) == ReplayStatus::Ok);
}

PF_TEST(replay_small_shift_keeps_recent_history) {
    ReplayWindow w;
    w.commit(10);
    w.commit(12);                                      // shift 2
    PF_CHECK(w.check(10) == ReplayStatus::Replay);
    PF_CHECK(w.check(12) == ReplayStatus::Replay);
    PF_CHECK(w.check(11) == ReplayStatus::Ok);
}

PF_TEST(replay_big_jump_resets_window) {
    ReplayWindow w;
    w.commit(1);
    w.commit(1000);
    PF_CHECK(w.check(1) == ReplayStatus::TooOld);
    PF_CHECK(w.check(1000) == ReplayStatus::Replay);
    PF_CHECK(w.check(999) == ReplayStatus::Ok);
}

PF_TEST(replay_commit_of_stale_or_seen_id_changes_nothing) {
    ReplayWindow w;
    w.commit(100);
    w.commit(100);
    w.commit(1);                                       // too old: ignored
    PF_CHECK_EQ(w.highest(), 100u);
    PF_CHECK(w.check(99) == ReplayStatus::Ok);
}

PF_TEST(replay_accepts_max_id_without_wraparound) {
    ReplayWindow w;
    w.commit(0xFFFFFFFEu);
    PF_CHECK(w.check(0xFFFFFFFFu) == ReplayStatus::Ok);
    w.commit(0xFFFFFFFFu);
    PF_CHECK(w.check(0xFFFFFFFFu) == ReplayStatus::Replay);
    PF_CHECK(w.check(1) == ReplayStatus::TooOld);      // no wrap back to low ids
}

PF_TEST(replay_sequential_stream_has_no_false_positives) {
    ReplayWindow w;
    for (uint32_t i = 1; i <= 1000; ++i) {
        PF_REQUIRE(w.check(i) == ReplayStatus::Ok);
        w.commit(i);
    }
    for (uint32_t i = 1; i <= 1000; ++i)
        PF_REQUIRE(w.check(i) != ReplayStatus::Ok);    // everything now replay or too old
}
