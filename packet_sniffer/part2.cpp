#include <iostream>
#include <pcap.h>
#include <vector>
#include <map>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <climits>
#include <csignal>
#include <fstream>
#include <cstring>

using namespace std;

#define SNAP_LEN 1518
volatile sig_atomic_t stopCapture = 0; 
pcap_t *handle = nullptr;

int hidden_message_count = 0; // Counter for packets containing the hidden message
int total_packet_count = 0; // Counter for total packets captured
ofstream logFile("hidden_messages.txt"); // Open log file

// Signal handler for Ctrl+C
void handleSignal(int signum) {
    stopCapture = 1;
    if (handle) {
        pcap_breakloop(handle);
    }
}

// Helper function to calculate checksum
unsigned short calculate_checksum(unsigned short* buffer, int size) {
    unsigned long sum = 0;

    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }

    if (size == 1) {
        sum += *(unsigned char*)buffer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

// Callback function for processing packets
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    total_packet_count++; // Increment total packet count for each packet captured

    int packetSize = pkthdr->len;

    // Parse IP header
    struct ip *ipHeader = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)
    int ipHeaderLength = ipHeader->ip_hl << 2;

    // Parse the protocol used
    string protocol;
    if (ipHeader->ip_p == IPPROTO_TCP) {
        protocol = "TCP";
        struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + ipHeaderLength);
        
        // Filter by source port 1579
        uint16_t sourcePort = ntohs(tcpHeader->th_sport);
        if (sourcePort != 1579) {
            return; // Skip this packet if source port is not 1579
        }

        // Pointer to the payload (after TCP header)
        const u_char* payload = packet + 14 + ipHeaderLength + (tcpHeader->th_off << 2);
        int payloadSize = pkthdr->len - (14 + ipHeaderLength + (tcpHeader->th_off << 2));

        // Search for "CS331" in payload
        if (payloadSize > 0) {
            string payloadStr(reinterpret_cast<const char*>(payload), payloadSize);
            if (payloadStr.find("CS331") != string::npos) {
                hidden_message_count++;
                
                // Compute TCP checksum
                unsigned short tcpChecksum = calculate_checksum((unsigned short*)tcpHeader, ntohs(ipHeader->ip_len) - ipHeaderLength);

                // Log to file: Answer for Q3, Q4, and Q1
                logFile << "Protocol used: " << protocol << endl;
                logFile << "TCP segment checksum: 0x" << hex << tcpChecksum << dec << endl;
                logFile << "Hidden message found: " << payloadStr << endl;
            }
        }
    } 
    else if (ipHeader->ip_p == IPPROTO_UDP) {
        protocol = "UDP";
        struct udphdr *udpHeader = (struct udphdr *)(packet + 14 + ipHeaderLength);
        uint16_t sourcePort = ntohs(udpHeader->uh_sport);

        // Skip UDP packets for this task (as per the hint, we focus on source port 1579 in TCP)
        return;
    }

    cout << "Packet Captured! Size: " << packetSize << " bytes" << endl;
    
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
    handle = pcap_open_live(device->name, SNAP_LEN, 1, 1000, errbuf);
    if (!handle) {
        cerr << "Error opening device: " << errbuf << endl;
        return 1;
    }

    pcap_freealldevs(alldevs);
    signal(SIGINT, handleSignal);

    cout << "Listening for packets... Press Ctrl+C to stop.\n";

    // Start capturing packets
    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_close(handle);

    cout << "\nCapture complete.\n";
    cout << "Total packets captured: " << total_packet_count << endl;
    cout << "Total packets containing hidden message: " << hidden_message_count << endl;

    // Log total counts to file
    logFile << "Total packets captured: " << total_packet_count << endl;
    logFile << "Total packets containing the hidden message: " << hidden_message_count << endl;
    logFile.close(); // Close the log file after writing

    return 0;
}
