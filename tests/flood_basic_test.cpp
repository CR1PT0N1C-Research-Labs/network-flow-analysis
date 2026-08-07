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

TEST_CASE("SYN Flood detection test") {
    auto monlib = test_monlib_init();
    
    CHECK(test_monlib_pcap(monlib, "test_data/synflood.cap"));
    
}
