#ifndef _DNS_INCLUDE
#define _DNS_INCLUDE

#include <memory>
#include <cstring>

enum QueryType {
    A = 1,
    PTR = 12
};
struct DNSFlag {
    unsigned char RD:1;
    unsigned char TC:1;
    unsigned char AA:1;
    unsigned char OPCODE:4;
    unsigned char QR:1;
    unsigned char RCODE:4;
    unsigned char ZERO:3;
    unsigned char RA:1;
//    unsigned char QR:1;
//    unsigned char OPCODE:4;
//    unsigned char AA:1;
//    unsigned char TC:1;
//    unsigned char RD:1;
//    unsigned char RA:1;
//    unsigned char ZERO:3;
//    unsigned char RCODE:4;
};
struct DNSHeader {
    unsigned short descriptor;
    DNSFlag flag;
    unsigned short questionCount;
    unsigned short resourceRecourdCount;
    unsigned short authorizationRecordCount;
    unsigned short extraSourceCount;
};
struct DNSType {
    unsigned short type;
    unsigned short typeClass;
};

struct DNSQuestion {
    unsigned char queryName[4096];
    DNSType type;
//    unsigned short queryType=QueryType::A;
//    unsigned short queryClass=1;
};

struct DNSMessage {
    typedef std::shared_ptr<std::pair<unsigned char *, int>> DNSMessageData;
    DNSHeader dnsHeader;
    DNSQuestion dnsQuestion;

    DNSMessageData toRequestData();
};

struct DNSResourceExtraInfo {
    DNSType type;
    int liveTime;
    unsigned short resourceDataLength;
};

struct DNSResourceRecord {
    char domainName[4096];
    DNSResourceExtraInfo extraInfo;
    char dataResrouce[4096];
};


#endif