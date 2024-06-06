# In-band Network Telemetry
Team: Máté Fekete, Nóra Szécsi and Róbert Fikó (alphabetical order)


## Background
- paper: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=10284901
- implementation plan: [impl.md](impl.md)

## Start

1. The first step is to start the topology: `sudo p4run --conf p4app_digest.json`
2. It is needed to sniff on `h2` to see the packages
   1. Start a console on `h2`: `mx h2`
   2. Start the sniffer: `python scapy_sniff.py`
3. Now you can send packages from `h1`
   1. Start a console on `h1`: `mx h1`
   2. Send a package to `h2`: `python scapy_send.py`