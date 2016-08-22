#include <iostream>
#include <sys/socket.h>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <algorithm>
#include <cassert>
#include <regex>
#include <string>
#include <unordered_set>
#include "include/util.h"
#include "include/dns.h"

//unsigned char arr[4096];

typedef std::shared_ptr<sockaddr_in> IP4Address;
typedef std::shared_ptr<u_char> DNSResponseDatagram;

using std::cout;
using std::cerr;
using std::endl;

void handleError(const std::string &errorStr, bool withErrno, bool stopExecution) {
    cerr << (errorStr.c_str()) << " ";
    if (withErrno)
        cerr << strerror(errno) << "\n";
    if (stopExecution)
        exit(EXIT_FAILURE);
}

int InitSocket() {
    int socketDescriptor = socket(AF_INET, SOCK_DGRAM, 0);//using UDP
    if (socketDescriptor < 0) {
        handleError("socket error", true, true);
    }

    struct timeval tv_out; //set timeout
    tv_out.tv_sec = 10;//wait for 10 seconds.
    tv_out.tv_usec = 0;
    if (setsockopt(socketDescriptor, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) != 0) {
        handleError("setsockopt error", true, true);
    }


    // setvbuf(, buf, _IOFBF,  BUFSIZ);
    return socketDescriptor;
}

IP4Address allocateIP4Address() {
    sockaddr_in *address = new sockaddr_in;
    address->sin_family = AF_INET;
    address->sin_port = htons(53);
    int ipResult = inet_pton(AF_INET, "114.114.114.114", &(address->sin_addr));
    if (ipResult < 0) {
        handleError("inet_pton error", true, true);
    }
    return IP4Address(address);
}


//@resourceSections -> resource record sections from dns server. @beginIndex -> index of current record.
//@returnValue -> index of next record
int showResourceRecord(u_char *resouceSections, int beginIndex) {

    assert(resouceSections != nullptr);

    if (beginIndex < 0) {
        throw std::invalid_argument("beginIndex < 0");
    }
    u_char *currentResourceRecord = resouceSections + beginIndex;
    size_t globalCurrentPosition = 0;
    u_char *domainName = currentResourceRecord + globalCurrentPosition;
    size_t domainLength = strlen((char *) domainName);
    if (domainLength == 0) {//0 indicates that this is a root descriptor;
        globalCurrentPosition += 1;
    }
    else {
        globalCurrentPosition += domainLength; //skip the domain name field and set position to the head of resource info fields;
    }

    DNSResourceExtraInfo *responseInfo = (DNSResourceExtraInfo *) (currentResourceRecord + globalCurrentPosition);

    int type = ntohs(responseInfo->type.type);
    int typeClass = ntohs(responseInfo->type.typeClass);
    size_t liveTime = ntohl(responseInfo->liveTime);
    size_t resourceDataLength = ntohs(responseInfo->resourceDataLength);

    cout << "Type: " << type << " | Class : " << typeClass << endl;
    cout << "live time: " << liveTime << endl;
    cout << "resource data length: " << resourceDataLength << endl;

    globalCurrentPosition += 10;//set position  to the head of resource data;

    std::shared_ptr<u_char> resourceData(new u_char[resourceDataLength]);
    memcpy(resourceData.get(), currentResourceRecord + globalCurrentPosition, resourceDataLength);

    if (isIPType(type)) {//if type is 1,then convert it to characteristic presentation.
        char ip[16];
        if (inet_ntop(AF_INET, resourceData.get(), ip, 16) < 0) {
            handleError("inet_ntop (in showResourceRecord) error", true, true);
        };
        cout << "IP:" << ip << "\n" << endl;
    }
//    else if(isCNAMEType(type)){
//        cout << "Address:" << restoreQueryName(resourceData.get(), resourceDataLength) << "\n" << endl;
//    }
    else { //else restore the domain presentation.
        try{
            cout << "Address:" << restoreQueryName(resourceData.get(), resourceDataLength) << "\n" << endl;
        }
        catch(std::logic_error& err){
            handleError(err.what(),false,true);
        }

    }

    globalCurrentPosition += resourceDataLength + beginIndex;//skip to next resource record, so putting an additional 1
    return globalCurrentPosition;
}
int showSingleResourceRecord(u_char *currentResourceRecord, int count) {
    int nextRecordPosition = 0;
    for (int i = 0; i < count; i++) {
        nextRecordPosition = showResourceRecord(currentResourceRecord, nextRecordPosition);
    }
    return nextRecordPosition;
}

void printDNSDatagram(DNSResponseDatagram dnsDatagram,size_t dataGramSize) {
    assert(dnsDatagram.get() != nullptr);
    u_char *receivedMessage = dnsDatagram.get();

    //show dns resonse header
    DNSHeader *dnsHeader = (DNSHeader *) receivedMessage;
    cout << "-----------------DNS Response-----------------" << "\n";
    cout << "Descriptor:" << ntohs(dnsHeader->descriptor) << " | Flags -> ";

    //dns flags.
    DNSFlag *flag = (DNSFlag *) &receivedMessage[2];
    cout << "QR:" << (flag->QR == 1) << " | OPCODE:" << (flag->OPCODE == 1) << " | AA:" << (flag->AA == 1) << " | TC:"
         << (flag->TC == 1) << " | RD:" << (flag->RD == 1) << " | RA:" << (flag->ZERO == 1) << " | RCODE:"
         << (flag->RCODE == 1) << "\n";

    //dns question count.
    cout << "Question Count:" << ntohs(dnsHeader->questionCount) << " | Resource Record Count:"
         << ntohs(dnsHeader->resourceRecourdCount) << "\n";

    //dns the other three filed values.
    cout << "Authorized Resource Record Count:" << ntohs(dnsHeader->authorizationRecordCount) << " | "
         << "Extra Resource Record Count:" << ntohs(dnsHeader->extraSourceCount) << "\n";

    // show dns question section.
    cout << "-----------------Question-----------------" << "\n";
    u_char *dnsQuestionName = &receivedMessage[12];
    size_t dnsQuestionNameLength = strlen((char *) dnsQuestionName);
    try{
        cout << restoreQueryName(dnsQuestionName, dnsQuestionNameLength) << "\n";
    }
    catch(std::logic_error& err){
        handleError(err.what(),false,true);
    }

    DNSType *question = (DNSType *) &receivedMessage[12 + dnsQuestionNameLength + 1];
    cout << "Type:" << ntohs(question->type) << " | Class:" << ntohs(question->typeClass) << "\n";


    cout << "-----------------Resource Recourds-----------------" << "\n";
    //show resource record sections.
    u_char *resourceSectionHead = &receivedMessage[12 + dnsQuestionNameLength + 1 + 4];
    int resourceRecourdCount = ntohs(dnsHeader->resourceRecourdCount);
    int nextRecordPosition = showSingleResourceRecord(resourceSectionHead, resourceRecourdCount);

    cout << "-----------------Authorized Recourds-----------------" << "\n";
    //show resource record sections.
    u_char *authorizedResourceSectionHead = resourceSectionHead + nextRecordPosition;
    int authorizedResourceRecourdCount = ntohs(dnsHeader->authorizationRecordCount);
    nextRecordPosition = showSingleResourceRecord(authorizedResourceSectionHead, authorizedResourceRecourdCount);

    cout << "-----------------Extra Recourds-----------------" << "\n";
    u_char *extraResourceSectionHead = resourceSectionHead + nextRecordPosition;
    int extraResourceRecourdCount = ntohs(dnsHeader->extraSourceCount);
    nextRecordPosition = showSingleResourceRecord(extraResourceSectionHead, extraResourceRecourdCount);

    cout << "-----------------End DNS Response-----------------" << "\n";
}

void sendDNSQuery(int socketDescriptor, IP4Address address, socklen_t addressLength, DNSMessage::DNSMessageData data) {
    int result = sendto(socketDescriptor, data->first, data->second, 0, (sockaddr *) address.get(), addressLength);
    if (result < 0) {
        handleError("sendto (int sendDNSQuery) error", true, true);
    }
}

DNSResponseDatagram receiveDNSInfo(int socketDescriptor,size_t *length) {
    u_char *receivedMessage = new u_char[4096];

    *length= recvfrom(socketDescriptor, receivedMessage, 4096, 0, NULL, NULL);
    if (*length < 0) {
        handleError("recvfrom (int receiveDNSInfo) error", true, true);
    }
    return DNSResponseDatagram(receivedMessage);
}

bool ValidateHostName(const std::string &hostName) {
    if (hostName.size() > 63 || hostName.size() == 0) {
        return false;
    }
//    std::regex urlRegex("^(www.)?[a-z0-9\\-]+\\.(com|cn)$");
//    std::cmatch sm;
//    if(std::regex_match(hostName.c_str(),sm, urlRegex)){
//        return true;
//    }
    return true;
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        handleError("please input the domain name.", false, true);
    }
//    if (!ValidateHostName(hostName)) {
//        handleError("host name is invalid.",false,true);
//    }
    std::string hostName = argv[1];//argv[1]: domain name
    int socketDescriptor = InitSocket();
    IP4Address address = allocateIP4Address();

    DNSMessage dnsMessage;
    fillDNSRequest(hostName, QueryType::A, dnsMessage); // set the fields of DNSMessage

    DNSMessage::DNSMessageData data = dnsMessage.toRequestData();

    sendDNSQuery(socketDescriptor, address, sizeof(*address), data); //send dns response from dns server

    size_t responseMessageSize=0;
    DNSResponseDatagram responseMessage = receiveDNSInfo(socketDescriptor,&responseMessageSize); //receive dns response from dns server

    printDNSDatagram(responseMessage,responseMessageSize);//print dns response datagram
    //cout << "received dns message" << endl;
    return 0;
}




