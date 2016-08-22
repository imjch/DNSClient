
#ifndef DNS_UTILITY_H
#define DNS_UTILITY_H

#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <netinet/in.h>
#include "../include/dns.h"

void split(const std::string &s, char c, std::vector<std::string> &v);

//when constructing dns query name, using a byte to store the count of the query name, not char!
//note that because of the validation of hostName , so we can assume that hostName if valid.
void constructQueryName(std::string &hostName, unsigned char *host);

//restore the query name, for example , 3www5baidu3com -> www.baidu.com
std::string restoreQueryName(const unsigned char *queryName, size_t length);

//indicating current whether the dns response type is IP or not
bool isIPType(int type);

bool isCNAMEType(int type);

//bool ValidateHostName(std::string hostName);


void fillDNSQuestion(std::string &hostName, QueryType queryType, DNSQuestion &dnsQuestion);

void fillDNSHeaeder(DNSHeader &header);

void fillDNSRequest(std::string &hostName, QueryType queryType, DNSMessage &dnsMesssage);



#endif
