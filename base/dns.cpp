#include "../include/dns.h"

//construct a binary datagram which is used to request the dns server.
DNSMessage::DNSMessageData DNSMessage::toRequestData() {
    unsigned char data[4096];
    DNSHeader *newDNSHeader = reinterpret_cast<DNSHeader *> (data);
    //construct dns request header
    newDNSHeader->authorizationRecordCount = this->dnsHeader.authorizationRecordCount;
    newDNSHeader->descriptor = this->dnsHeader.descriptor;
    newDNSHeader->extraSourceCount = this->dnsHeader.extraSourceCount;
    newDNSHeader->questionCount = this->dnsHeader.questionCount;
    newDNSHeader->resourceRecourdCount = this->dnsHeader.resourceRecourdCount;
    newDNSHeader->flag = this->dnsHeader.flag;
    //construct queryQuestion Name of dns request

    char *queryName = reinterpret_cast<char *>(&data[sizeof(DNSHeader)]);
    size_t queryNameLength = strlen((const char *) dnsQuestion.queryName);
    memcpy(queryName, dnsQuestion.queryName, queryNameLength);//copy query name

    //construct queryQuestion type of dns request
    DNSType *newDNSQuestion = reinterpret_cast<DNSType *>(&data[sizeof(DNSHeader) + queryNameLength + 1]);
    newDNSQuestion->type = dnsQuestion.type.type;
    newDNSQuestion->typeClass = dnsQuestion.type.typeClass;
    return DNSMessageData(new std::pair<unsigned char *, int>(data, 12 + queryNameLength + 1 + 4));
}





//        DNSQuestion* newDNSQuestion=reinterpret_cast<DNSQuestion*>(&data2[sizeof(DNSHeader)]);
//        using namespace std;
//        cout<<newDNSQuestion<<endl;
//
//        cout<<&newDNSQuestion->queryName<<endl;
//        char* aaa=reinterpret_cast<char*>(&data2[sizeof(DNSHeader)]);
//        printf("%p\n",aaa);

//assign values to DNSQuestion is too complex work it done perfectly... try another way: encapsulate the type and class to a entity.
//        char* newDNSQuestion=reinterpret_cast<char*>(&data2[sizeof(DNSHeader)+queryNameLength+1]);
//        char* oldDNSQuestion=reinterpret_cast<char*>(((char*)&dnsQuestion)+8);
//        memcpy(newDNSQuestion,oldDNSQuestion,4);
