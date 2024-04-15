# Implementation plan
_for In-band Network Telemetry_

Team: Máté Fekete, Nóra Szécsi and Róbert Fikó (alphabetical order)

## Open questions
1. Are there more SRH headers, if not, what is the next header?
2. Is there one INT header or not? If there is one, all of the switches append their telemetry data to it?
3. What happens if the packet exceeds the MTU, (so M bit is flipped, in the INT header)? We wait for the next packet? What kind of headers should/will it have?
4. Hop ML(5 bits) indicates the amount of metadata inserted by
switches, RemainingHopCnt(8 bits) indicates the number of remaining switches that are allowed to add their metadata to the packet. Why is RemainingHopCnt larger than Hop ML? (5 vs 8 bits)
5. What should be the format of this assignment, Markdown is fine. or PDF? or...?
6. How to solve the forwarding of the Probe? Is there any implementation of SRH routing? 

## Goals
- process INT instructions in SRv6 labels
- store the telemetry values in an INT header
- generate test traffic
- SRv6 header processing and routing

## Plan

### 1. Starting project
There are many projects in the lab repository, one will be used as a starting off and the topology and tests will be modified as needed. The starting project should contain hosts and switches, but most of them contains.

Basic headers, like Ethernet headers and other things, will be used from the start project.

### 2. Design the topology
As the research paper has examples of a topology of six switches, two hosts and a server, we will use this exact same network topology. 

![pics/topology.png](pics/topology.png)
_Picture source: research paper_


### 3. Server in the topology
The project requires a server which can receive requests from the Business Application to collect telemetry.
In this project, a really simple Python script will be the "Business Application" which will simulate a real one.

### 4. Path Planning Algorithm
In the provided research paper, there is Algorithm 2, which describes how to find the path for the telemetry path. It needs to be implemented

#### 4.1 Prototype implementation, PoC (Proof of Concept)
In the first iteration of the implementation the switches will only report back some basic data, like they are alive, or something like that.

### 5. Implementation of Probe
The Probe is the data/packet which is sent out by the server to a switch, with the types of telemetries which needs to be collected and the correct path.

![pics/probe.png](pics/probe.png)
_Picture source: research paper_

#### 5.1 INT header and Metadata stack
The implementation of the INT header and Metadata stack is required so the network device knows what kind of telemetry is required and other metadata. The structure of the metadata is the following.
The INT header is constructed by the instruction mapping subsystem, and has the following parts:

- `Ver` (4 bits): indicates the INT metadata header version
- `Flags` (2 bits): indicate whether to allow packet duplication
- `M` (1 bit): indicates whether the packet size exceeds the maximum transmission unit (MTU)
- `Hop ML` (5 bits): indicates the amount of metadata inserted by switches
- `RemainingHopCnt` (8 bits): indicates the number of remaining switches that are allowed to add their metadata to the packet
- `Instruction Bitmap` (11 bits): indicates the type of metadata to be collected
- `Reserved`: is a reserved bit

![pics/metadata.png](pics/metadata.png)
_Picture source: research paper_
 

### 6. Implementation of the SRH (SRv6) header
The Segment Routing Header contains the path, which should be used to traverse the path. 
The SRH header is constructed by the route planning subsystem, and this SRv6 header is attached to the payload.

#### 6.1 SRv6 header
The SRv6 header is crucial during routing, it consists of the following parts:
- `Next Header` (8 bits): indicates the next header type
- `Hdr Ext Len` (8 bits): indicates the SRH length
- `Routing Type` (8 bits): indicates the SRH type
- `Segments Left` (8 bits): indicates the remaining SRv6 label quantity
- `Last Entry` (8 bits): points to the index of the last label
- `Flags` (8 bits): is a reserved byte
- `Tag` (16 bits): indicates the classification of the data packet
- `Segment List[n]` (128 bits): indicates the IPv6 loopback address of each switch that forwards the data packet.


#### 6.2 SRv6 Label stack
On the SRv6 label stack, there are the routing segments, where the packet should be sent. After the packet is processed the address of the switch is removed from the stack.


### 7. Implement the forwarding of the probes in switches
Implement custom probes using both INT and SRv6 headers, to meet specific telemetry requirements. These probes are developed to gather telemetry data as they navigate through the network. 
The capabilities of SRv6 are needed to specify the telemetry path in the network, by using the SRv6 Segment Routing Label (SRL) stack. 

