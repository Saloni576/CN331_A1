#include <iostream>
#include <pcap.h>
#include <vector>
#include <map>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <climits>
#include <csignal>
#include <fstream>

using namespace std;

// Struct to store packet statistics
struct PacketStats {
    int totalPackets = 0;
    long long totalBytes = 0;
    int minPacketSize = INT_MAX;
    int maxPacketSize = 0;
    vector<int> packetSizes;
    map<int, int> sizeDistribution; // Histogram (size -> frequency)
    map<string, long long> sourceDestinationFlows; // Data transferred per flow
    map<string, int> sourceIPFlows; // Source IP flow counts
    map<string, int> destinationIPFlows; // Destination IP flow counts
};

// Global variables
volatile sig_atomic_t stopCapture = 0; 
pcap_t *handle = nullptr;

// Signal handler for Ctrl+C
void handleSignal(int signum) {
    stopCapture = 1;
    if (handle) {
        pcap_breakloop(handle);
    }
}

// Callback function for processing packets
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PacketStats *stats = (PacketStats *)userData;
    
    int packetSize = pkthdr->len;
    stats->totalPackets++;
    stats->totalBytes += packetSize;
    stats->minPacketSize = min(stats->minPacketSize, packetSize);
    stats->maxPacketSize = max(stats->maxPacketSize, packetSize);
    stats->packetSizes.push_back(packetSize);
    stats->sizeDistribution[packetSize]++;

    // Parse IP header
    struct ip *ipHeader = (struct ip *)(packet + 14); // 14 is Ethernet header length
    char sourceIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipHeader->ip_src, sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ipHeader->ip_dst, destIP, INET_ADDRSTRLEN);

    // Parse TCP header (for ports)
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + (ipHeader->ip_hl << 2));
    uint16_t sourcePort = ntohs(tcpHeader->th_sport);
    uint16_t destPort = ntohs(tcpHeader->th_dport);

    string sourceDest = string(sourceIP) + ":" + to_string(sourcePort) + " -> " + string(destIP) + ":" + to_string(destPort);

    // Track flow statistics
    stats->sourceDestinationFlows[sourceDest] += packetSize;
    stats->sourceIPFlows[sourceIP]++;
    stats->destinationIPFlows[destIP]++;

    cout << "Packet Captured! Size: " << packetSize << " bytes | Total Packets: " << stats->totalPackets << endl;

    if (stopCapture) {
        pcap_breakloop(handle);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find network interfaces
    pcap_if_t *alldevs, *device;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding network interfaces: " << errbuf << endl;
        return 1;
    }

    device = alldevs;
    if (!device) {
        cerr << "No network interfaces found!" << endl;
        return 1;
    }
    cout << "Using device: " << device->name << endl;

    // Open network interface for live packet capture
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Error opening device: " << errbuf << endl;
        return 1;
    }

    pcap_freealldevs(alldevs);
    signal(SIGINT, handleSignal);

    PacketStats stats;
    cout << "Listening for packets... Press Ctrl+C to stop.\n";

    // Start capturing packets
    pcap_loop(handle, 0, packetHandler, (u_char *)&stats);

    pcap_close(handle);

    // Calculate average packet size
    double avgPacketSize = (stats.totalPackets > 0) ? (double)stats.totalBytes / stats.totalPackets : 0;

    // Save histogram data for Python plotting
    ofstream histFile("histogram_data.csv");
    for (auto &[size, freq] : stats.sizeDistribution) {
        histFile << size << "," << freq << "\n";
    }
    histFile.close();

    // Write statistics to a file
    ofstream outputFile("packet_statistics.txt");
    if (!outputFile) {
        cerr << "Error opening output file" << endl;
        return 1;
    }

    outputFile << "Total Packets: " << stats.totalPackets << endl;
    outputFile << "Total Data Transferred: " << stats.totalBytes << " bytes" << endl;
    outputFile << "Min Packet Size: " << stats.minPacketSize << " bytes" << endl;
    outputFile << "Max Packet Size: " << stats.maxPacketSize << " bytes" << endl;
    outputFile << "Avg Packet Size: " << avgPacketSize << " bytes" << endl;

    // Write unique source-destination pairs
    outputFile << "\nUnique Source-Destination Pairs:" << endl;
    for (auto &flow : stats.sourceDestinationFlows) {
        outputFile << flow.first << " -> " << flow.second << " bytes transferred" << endl;
    }

    // Write source IP flow counts
    outputFile << "\nSource IP Flow Counts:" << endl;
    for (auto &flow : stats.sourceIPFlows) {
        outputFile << flow.first << " : " << flow.second << " flows" << endl;
    }

    // Write destination IP flow counts
    outputFile << "\nDestination IP Flow Counts:" << endl;
    for (auto &flow : stats.destinationIPFlows) {
        outputFile << flow.first << " : " << flow.second << " flows" << endl;
    }

    // Find the source-destination pair with the most data transferred
    string maxFlowPair;
    long long maxData = 0;
    for (auto &flow : stats.sourceDestinationFlows) {
        if (flow.second > maxData) {
            maxData = flow.second;
            maxFlowPair = flow.first;
        }
    }

    outputFile.close();

    cout << "\nCapture complete.\n";
    cout << "Total Packets: " << stats.totalPackets << endl;
    cout << "Total Data Transferred: " << stats.totalBytes << " bytes" << endl;
    cout << "Min Packet Size: " << stats.minPacketSize << " bytes" << endl;
    cout << "Max Packet Size: " << stats.maxPacketSize << " bytes" << endl;
    cout << "Avg Packet Size: " << avgPacketSize << " bytes" << endl;
    cout << "Most data transferred by: " << maxFlowPair << " with " << maxData << " bytes" << endl;
    cout << "Packet size histogram saved to histogram_data.csv." << endl;
    cout << "Detailed statistics saved to packet_statistics.txt" << endl;

    return 0;
}
