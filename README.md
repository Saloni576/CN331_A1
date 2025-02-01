# CS 331: Computer Networks - Assignment 1

## Introduction
This assignment focuses on developing a raw packet sniffer and analyzing network traffic from a pre-captured PCAP file. The task involves replaying network traffic using `tcpreplay` and computing key metrics related to packet transmission.

## Setup & Execution

Create a folder named `packet_replayer` inside the directory where your git repository is cloned. Place the required PCAP file inside this `packet_replayer` folder. Then proceed with the next steps as instructed.

### 1. Compile C++ programs
```sh
cd packet_sniffer
g++ -o part1 part1.cpp -lpcap
g++ -o part2 part2.cpp -lpcap
```

This will create executables for both the files.

### 2. Start Packet Sniffing
Open **Terminal 1**:
```sh
cd packet_sniffer
sudo ./part1
```

### 3. Replay Packets for Part 1
Open **Terminal 2**:
```sh
cd packet_replayer
sudo tcpreplay -i eth0 --topspeed 4.pcap
```

After all packets have been sent, Terminal 2 will display the details of the transferred data. In Terminal 1, press `Ctrl+C` to stop the process. This will save the statistical data of the packets.
Now, `packet_statistics.txt` will contain the sniffed packet statistics, and `histogram_data.csv` will store data for the histogram plot.

### 4. Analyze and Process Data
Back in **Terminal 1**:
```sh
python part1.py
```

This will save the histogram in `part1_histogram.png`.

```sh
sudo ./part2
```

### 5. Replay Again for Part 2
```sh
cd packet_sniffer
sudo tcpreplay -i eth0 --topspeed 4.pcap
```

After all packets have been sent, Terminal 2 will display the details of the transferred data. In Terminal 1, press `Ctrl+C` to stop the process. This will save the statistical data of the packets.
Now, `hidden_messages.txt` will contain the data required to answer the questions in Part 2.

## Notes
- `libpcap` must be installed (`sudo apt install libpcap-dev`).
- Run commands with `sudo` for packet capture and replay.
- Replace `eth0` with your actual network interface (`ifconfig` to check).
