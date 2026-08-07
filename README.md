# Network Flow Analysis & SYN Flood Detection

Low-level network traffic analysis and attack detection implemented in C as an extension of the `monlib` packet-processing library.

The project combines two related tasks: first, extracting packet and flow statistics from captured network traffic, and second, extending the same packet-processing pipeline with stateful detection of TCP SYN Flood attacks.

---

## Project Overview

The implementation processes captured Ethernet frames and extracts information from layers L2–L4 without copying packet data.

The first part focuses on:

* Ethernet and IPv4 packet parsing
* TCP and UDP identification
* TCP flag inspection
* source and destination port statistics
* bidirectional flow tracking
* packet and byte statistics
* average packet and flow sizes

The second part extends this functionality with a stateful heuristic for detecting TCP SYN Flood behaviour.

The resulting pipeline is:

```text
PCAP
  │
  ▼
Ethernet parsing
  │
  ▼
IPv4 parsing
  │
  ▼
TCP / UDP parsing
  │
  ├── Packet statistics
  ├── TCP flags
  ├── Port statistics
  ├── Flow tracking
  │
  └── SYN Flood detection
          │
          ▼
       Alert
```

---

# 1. Packet and Flow Statistics

## Zero-Copy Packet Parsing

The main packet-processing function is `monlib_process`.

Packets are processed directly from the supplied memory buffer. The implementation advances pointers through the packet instead of creating copies of individual protocol headers or payloads.

### Layer 2 — Ethernet

The Ethernet header is validated first and the EtherType determines the next protocol layer.

IPv4 and IPv6 traffic are distinguished using:

```c
eth->h_proto
```

converted from network byte order with `ntohs()`.

---

### Layer 3 — IPv4

For IPv4 packets the implementation extracts:

* source IP address
* destination IP address
* transport protocol
* variable IPv4 header length

The transport-layer offset is calculated from the IPv4 `IHL` field.

IPv6 packets are counted separately but are not further processed by the current implementation.

---

### Layer 4 — TCP / UDP

The parser identifies TCP and UDP packets and extracts:

* source port
* destination port
* TCP SYN flag
* TCP FIN flag

The statistics layer therefore provides both protocol-level and transport-level information about the captured traffic.

---

# 2. Flow Tracking

The implementation maintains a table of observed network flows.

A flow represents a logical bidirectional communication between two IP addresses.

Therefore:

```text
A → B
B → A
```

are associated with the same flow.

For every tracked flow the implementation maintains:

* source IP
* destination IP
* source port
* destination port
* transport protocol
* packet count
* byte count

The flow table is preallocated with space for 50 flows.

---

# 3. Aggregated Statistics

The `monlib_get_stats()` function calculates the final aggregate metrics.

The implementation reports:

* total packet count
* IPv4 packet count
* IPv6 packet count
* TCP packet count
* UDP packet count
* TCP SYN count
* TCP FIN count
* maximum source port
* minimum destination port
* number of flows
* average packet size
* average packets per flow
* average bytes per flow

Average values are calculated using integer division.

---

# 4. Validation Against PCAP Data

The implementation was validated using the PCAP file:

```text
test_data/http.cap
```

The expected values were extracted from the captured traffic and incorporated into the Doctest-based test suite.

The validation checks:

| Metric                   | Expected value |
| ------------------------ | -------------: |
| IPv4 packets             |             43 |
| IPv6 packets             |              0 |
| TCP packets              |             41 |
| UDP packets              |              2 |
| TCP SYN packets          |              2 |
| TCP FIN packets          |              2 |
| Maximum source port      |           3372 |
| Minimum destination port |             53 |
| Unique flows             |              3 |
| Average packet size      |          583 B |
| Average packets / flow   |             14 |
| Average bytes / flow     |         8363 B |

The tests were compiled using the project's CMake/GCC toolchain and validated the parser and statistical calculations.

---

# 5. SYN Flood Detection

The second part of the project extends the original packet parser with detection of TCP SYN Flood behaviour.

A SYN Flood attempts to exhaust server resources by generating a large number of TCP connection attempts without completing the connection establishment process.

The detector therefore monitors the relationship between:

```text
SYN packets
      ↓
FIN + RST packets
```

A large number of SYN packets combined with very few connection-closing packets is treated as suspicious.

---

## Detection Algorithm

The detector follows four basic steps.

### 1. Track TCP RST packets

In addition to the existing SYN and FIN counters, the implementation maintains a `tcp_rsts` counter.

---

### 2. Calculate closed connections

The number of observed connection terminations is calculated as:

```text
closed = FIN + RST
```

If no closing packets have been observed, the divisor is set to `1` to prevent division by zero.

---

### 3. Require a minimum sample

Detection is only evaluated once more than 50 SYN packets have been observed.

This prevents the heuristic from triggering on very small traffic samples.

---

### 4. Evaluate SYN / closing-packet ratio

The detector calculates:

```text
SYN / (FIN + RST)
```

An alert is generated when the resulting integer ratio exceeds `5`.

The resulting alert is:

```text
ALERT: SYN Flood detected!
```

After an alert, the SYN, FIN and RST counters are reset so that another attack wave can subsequently be detected.

---

# 6. SYN Flood Simulation

An offline attack generator was created using Python and Scapy.

The generator creates:

* 120 TCP SYN packets
* 2 TCP RST packets

The packets use incrementing source ports to simulate multiple connection attempts.

This produces:

```text
SYN = 120
RST = 2

SYN / (FIN + RST)
= 120 / 2
= 60
```

Since:

```text
60 > 5
```

the detector should generate a SYN Flood alert.

The generated traffic is stored as:

```text
test_data/synflood.cap
```

---

# 7. Automated Testing

The Doctest test suite validates both the original network statistics functionality and the SYN Flood detection pipeline.

The SYN Flood test loads the generated PCAP through the same `monlib` processing path:

```cpp
TEST_CASE("SYN Flood detection test") {
    auto monlib = test_monlib_init();

    CHECK(test_monlib_pcap(monlib, "test_data/synflood.cap"));
}
```

This provides an offline and reproducible way of testing the detection logic without requiring a live network interface.

---

# Repository Structure

```text
network-flow-analysis/
│
├── README.md
├── LICENSE
│
├── src/
│   └── monlib.c
│
├── tests/
│   └── basic_test.cpp
│
├── tools/
│   └── synflood_gen.py
│
└── test_data/
    ├── http.cap
    └── synflood.cap
```

---

# Technologies

* C
* C++
* Python
* Scapy
* Doctest
* CMake
* GCC
* PCAP
* Linux networking headers

---

# Skills Demonstrated

* Low-level network packet parsing
* Zero-copy processing
* Ethernet / IPv4 / TCP / UDP analysis
* Network flow tracking
* TCP flag analysis
* PCAP-based testing
* Stateful network anomaly detection
* SYN Flood detection
* C/C++ testing
* Network security engineering

---

## Author

**CR1PT0N1C**

CR1PT0N1C Research Labs
