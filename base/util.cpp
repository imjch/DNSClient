
#include <cassert>
#include "../include/util.h"
#include <stdexcept>
#include <netinet/in.h>
#include "../include/dns.h"

void split(const std::string &str, char c, std::vector<std::string> &v) {
    if (str.size() == 0) {
        throw std::invalid_argument("parameter str is empty");
    }
    std::string::size_type i = 0;
    std::string::size_type j = str.find(c);

    while (j != std::string::npos) {
        v.push_back(str.substr(i, j - i));
        i = ++j;
        j = str.find(c, j);
    }
    if (j == std::string::npos)
        v.push_back(str.substr(i, str.length()));
}


void constructQueryName(std::string &hostName, unsigned char *host) {
    if (hostName.size() == 0) {
        throw std::invalid_argument("parameter hostName is invalid.");
    }
    if (!host) {
        throw std::invalid_argument("parameter host is invalid.");
    }

    std::vector<std::string> v;
    split(hostName, '.', v);
    hostName.clear();
    for_each(v.begin(), v.end(), [&hostName, &host](std::string &s) {
        *host = s.size();
        host++;
        memcpy(host, s.c_str(), s.size());
        host += s.size();
    });
}

// client has the responsibility to ensure the correctnes of the length of queryName,because of 2 bytes after domain name field;
std::string restoreQueryName(const unsigned char *domainName, size_t length) {
    if (!domainName) {
        throw std::invalid_argument("parameter queryName is null or empty.");
    }
    if(*domainName=='\0'||length==0){
        return std::string(".");
    }
//    assert(hostName);
//    assert(hostNameLength>2);

    unsigned char newQueryName[length*2]={0};
    unsigned char *newHostPos = newQueryName;
    const unsigned char *hostPos = domainName;

    while (hostPos != (domainName + length + 1)) {
        size_t count = *hostPos++;
        if(count>63){
            break;
        }
        if(count==0){
            *newHostPos++ = ' ';
            continue;
        }
        for (int i = 0; i < count; i++) {
            *newHostPos++ = *hostPos++;
        }
        *newHostPos++ = '.';
    }
    newHostPos='\0';
    return std::string((char*)newQueryName);
}

bool isIPType(int type) {
    assert(type >= 1);
    if (type == 1) {
        return true;
    }
    return false;
}

bool isCNAMEType(int type){
    assert(type >= 1);
    if (type == 5) {
        return true;
    }
    return false;
}

//bool ValidateHostName( std::string hostName) {
//    if (hostName.size() > 63 || hostName.size() == 0) {
//        return false;
//    }
//    std::regex urlRegex("^(www.)?[a-z0-9\\-]+\\.(com|cn)$");
//    if(std::regex_match(hostName,urlRegex)){
//        return true;
//    }
//    return false;
//}


void fillDNSQuestion(std::string &hostName, QueryType queryType, DNSQuestion &dnsQuestion) {
    assert(hostName.size() > 0);
    constructQueryName(hostName, dnsQuestion.queryName);
    //dnsQuestion.queryName="3www5baidu3com";
    dnsQuestion.type.typeClass = htons(1);//used to be 1, a internet address.
    dnsQuestion.type.type = htons(queryType);
}

void fillDNSHeaeder(DNSHeader &header) {
    header.descriptor = htons(9);//a magic number...
    header.questionCount = htons(1);
    header.resourceRecourdCount = 0;
    header.authorizationRecordCount = 0;
    header.extraSourceCount = 0;

    header.flag.QR = 0;// indicate that the message is used to request
    header.flag.OPCODE = 0;//standard query
    header.flag.AA = 1;//authoritative answer
    header.flag.TC = 0;//can be truncated or not
    header.flag.RD = 1;//tell the dns server that this query must be handled and the method is 'recursive'
    header.flag.RA = 1;//if dns server's query method is 'recursive', asign it 1
    header.flag.ZERO = 0;//it must be 0
    header.flag.RCODE = 0;//returned and assigned by dns server
}

void fillDNSRequest(std::string &hostName, QueryType queryType, DNSMessage &dnsMesssage) {

    assert(hostName.size() > 0);

    fillDNSHeaeder(dnsMesssage.dnsHeader);
    fillDNSQuestion(hostName, queryType, dnsMesssage.dnsQuestion);
}
