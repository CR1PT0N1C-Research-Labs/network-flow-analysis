#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "shared.hpp"

#include <iostream>
using namespace std;

TEST_CASE("Basic hash table api test") {
    auto monlib = test_monlib_init();
    auto hs_api = monlib->os_ops.hashtable;
    auto hashtable = hs_api.alloc();

    for(int i = 0; i < 32; i++) {
        auto content = new int;
        *content = i+10;
        auto hi = hs_api.item_alloc(i, content);
        hs_api.insert(hashtable, hi);
    }

    for(int i = 0; i < 64; i++) {
        auto li = hs_api.get(hashtable, i);
        if(i < 32) {
            CHECK(li != NULL);
            auto content = static_cast<int*>(hs_api.item_val(li));
            CHECK(content != NULL);
            CHECK(*content == i+10);
        } else {
            CHECK(li == NULL);
        }
    }

    int i = 0;
    hashtable_item_t item;
    auto iter = hs_api.iter_start(hashtable);
    while((item = hs_api.iter_next(iter)) != NULL) {
        i++;
        hs_api.remove(hashtable, item, iter);
        auto content = static_cast<int*>(hs_api.item_val(item));
        delete content;
    }
    hs_api.iter_stop(iter);
    CHECK(i == 32);
    hs_api.free(hashtable);
}

TEST_CASE("Basic example pcap http test") {
    auto monlib = test_monlib_init();
    CHECK(test_monlib_pcap(monlib, "test_data/http.cap"));

    auto stats = monlib_get_stats(monlib.get());

    // Basic packet counting
    CHECK(stats.packets == 43);
    CHECK(stats.ipv4_packets == 43);
    CHECK(stats.ipv6_packets == 0);
    CHECK(stats.tcp_packets == 41);
    CHECK(stats.udp_packets == 2);

    // TCP Flags
    CHECK(stats.tcp_syns == 2);
    CHECK(stats.tcp_fins == 2);

    // Port stats
    CHECK(stats.max_src_port == 3372);
    CHECK(stats.min_dst_port == 53);

    // Flows
    CHECK(stats.flows == 3);

    // Averages
    // 25091 bytes / 43 packets = 583
    CHECK(stats.avr_byte_len == 583);
    
    // 43 packets / 3 flows = 14
    CHECK(stats.avr_flow_p_len == 14);
    
    // 25091 bytes / 3 flows = 8363
    CHECK(stats.avr_flow_b_len == 8363);
}
