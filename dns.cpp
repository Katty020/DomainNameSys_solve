#include <iostream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <bits/stdc++.h>

void DNSResolver::__init() {
	dns_init(nullptr, 0);

	ctx_udns = dns_new(nullptr);
	if (!ctx_udns)
		throw std::system_error(ENOMEM, std::system_category(), strerror(ENOMEM));

	if (dns_init(ctx_udns, 0) < 0)
		THROW_ERRNO;
}

void DNSResolver::__fini() {
	if (ctx_udns) {
		fprintf(stderr,"__fini\n");
		dns_free(ctx_udns);
		ctx_udns = nullptr;
	}
}

void DNSResolver::__open() {
	if ((fd_udns = dns_open(ctx_udns)) < 0) {
		THROW_ERRNO;
	}

	struct sockaddr sa;
	socklen_t len = sizeof(sa);
	if (getsockname(fd_udns, &sa, &len))
		throw std::system_error(std::error_code(errno, std::system_category()), "getsockname");

	asio_socket = std::make_unique<boost::asio::ip::udp::socket>(asio_iosvc,
								     sa.sa_family == AF_INET ?
								     boost::asio::ip::udp::v4()
											     : boost::asio::ip::udp::v6(),
								     dns_sock(ctx_udns));
	// struct sockaddr sa;
	// socklen_t len = sizeof(sa);
	

	
}

void DNSResolver::io_wait_read() {
	fprintf(stderr,"io_wait_read\n");
	asio_socket->async_receive(boost::asio::null_buffers(),
				   boost::bind(&DNSResolver::iocb_read_avail, this));
}

void DNSResolver::iocb_read_avail() {
	fprintf(stderr,"iocb_read_avail\n");
	dns_ioevent(ctx_udns, time(nullptr));

	if (requests_pending)
		io_wait_read();
}

void DNSResolver::set_servers(const std::initializer_list<std::string> &__nameservers) {
	dns_add_serv(ctx_udns, nullptr);

	for (auto &it : __nameservers) {
		if (dns_add_serv(ctx_udns, it.c_str()) < 0) {
			THROW_ERRNO;
		}
	}
}

void DNSResolver::post_resolve() {
	requests_pending++;
	dns_timeouts(ctx_udns, -1, time(nullptr));
	io_wait_read();
}

void DNSResolver::dnscb_a4(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data) {
	auto *pd = (std::pair<DNSResolver *, A4Callback> *) data;
	pd->first->requests_pending--;

	std::vector<boost::asio::ip::address_v4> addrs;

	if (result) {
		for (uint32_t i = 0; i < result->dnsa4_nrr; i++) {
			std::array<unsigned char, 4> buf;
			memcpy(buf.data(), &result->dnsa4_addr[i].s_addr, 4);
			addrs.emplace_back(buf);
		}

		std::string_view cname(result->dnsa4_cname);
		std::string_view qname(result->dnsa4_qname);

		pd->second(DNS_E_NOERROR, addrs, qname, cname, result->dnsa4_ttl);
		free(result);
	} else {
		pd->second(dns_status(pd->first->ctx_udns), addrs, {}, {}, 0);
	}

	delete pd;
}

void DNSResolver::dnscb_a6(struct dns_ctx *ctx, struct dns_rr_a6 *result, void *data) {
	auto *pd = (std::pair<DNSResolver *, A6Callback> *) data;
	pd->first->requests_pending--;

	std::vector<boost::asio::ip::address_v6> addrs;

	if (result) {
		for (uint32_t i = 0; i < result->dnsa6_nrr; i++) {
			std::array<unsigned char, 16> buf;
			memcpy(buf.data(), &result->dnsa6_addr[i], 16);
			addrs.emplace_back(buf);
		}

		std::string_view cname(result->dnsa6_cname);
		std::string_view qname(result->dnsa6_qname);

		pd->second(DNS_E_NOERROR, addrs, qname, cname, result->dnsa6_ttl);
		free(result);
	} else {
		pd->second(dns_status(pd->first->ctx_udns), addrs, {}, {}, 0);
	}

	delete pd;
}

void DNSResolver::dnscb_txt(struct dns_ctx *ctx, struct dns_rr_txt *result, void *data) {
	auto *pd = (std::pair<DNSResolver *, TXTCallback> *) data;
	pd->first->requests_pending--;

	if (result) {
		std::vector<std::string_view> addrs;

		for (uint32_t i = 0; i < result->dnstxt_nrr; i++) {
			addrs.emplace_back((const char *) result->dnstxt_txt[i].txt, result->dnstxt_txt[i].len);
		}

		std::string_view cname(result->dnstxt_cname);
		std::string_view qname(result->dnstxt_qname);

		pd->second(DNS_E_NOERROR, addrs, qname, cname, result->dnstxt_ttl);
		free(result);
	} else {
		pd->second(dns_status(pd->first->ctx_udns), {}, {}, {}, 0);
	}

	delete pd;
}

void DNSResolver::dnscb_mx(struct dns_ctx *ctx, struct dns_rr_mx *result, void *data) {
	auto *pd = (std::pair<DNSResolver *, MXCallback> *) data;
	pd->first->requests_pending--;

	if (result) {
		std::vector<MXRecord> addrs;

		for (uint32_t i = 0; i < result->dnsmx_nrr; i++) {
			addrs.emplace_back(result->dnsmx_mx[i].priority, result->dnsmx_mx[i].name);
		}

		std::string_view cname(result->dnsmx_cname);
		std::string_view qname(result->dnsmx_qname);

		pd->second(DNS_E_NOERROR, addrs, qname, cname, result->dnsmx_ttl);
		free(result);
	} else {
		pd->second(dns_status(pd->first->ctx_udns), {}, {}, {}, 0);
	}

	delete pd;
}

void DNSResolver::dnscb_srv(struct dns_ctx *ctx, struct dns_rr_srv *result, void *data) {
	auto *pd = (std::pair<DNSResolver *, SRVCallback> *) data;
	pd->first->requests_pending--;

	if (result) {
		std::vector<SRVRecord> addrs;

		for (uint32_t i = 0; i < result->dnssrv_nrr; i++) {
			auto &r = result->dnssrv_srv[i];
			addrs.emplace_back(r.priority, r.weight, r.port, r.name);
		}

		std::string_view cname(result->dnssrv_cname);
		std::string_view qname(result->dnssrv_qname);

		pd->second(DNS_E_NOERROR, addrs, qname, cname, result->dnssrv_ttl);
		free(result);
	} else {
		pd->second(dns_status(pd->first->ctx_udns), {}, {}, {}, 0);
	}

	delete pd;
}

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t numQuestions;
    uint16_t numAnswers;
    uint16_t numAuthority;
    uint16_t numAdditional;
};

// Define the DNS question structure
struct DNSQuestion {
    string name;
    uint16_t recordType;
    uint16_t queryClass;
};

struct DNSAnswer {
    string name;
    uint16_t type;
    uint16_t queryClass;
    uint32_t ttl;
    uint16_t dataLength;
    // Data content (e.g. IP address)
};

int main() {
    DNSHeader header;
    DNSQuestion question;
    DNSAnswer answer[2]; // Assuming 2 answers, adjust as needed

    // Fill in header fields
    header.id = htons(22); // Use random ID
    header.flags = htons(0x0100); // Recursion desired bit set
    header.numQuestions = htons(1);
    header.numAnswers = htons(0);
    header.numAuthority = htons(0);
    header.numAdditional = htons(0);

    // Fill in question fields
    question.name = "dns.google.com"; // Change to your desired hostname
    question.recordType = htons(1); // Query type A (IPv4 address)
    question.queryClass = htons(1); // Query class IN (Internet)

    // Convert structs to byte strings
    std::string dnsMessage;
    dnsMessage.append(reinterpret_cast<const char*>(&header), sizeof(header));

    // Encode the question name
    std::string encodedName;
    const char* namePart = question.name.c_str();
    while (*namePart) {
        char length = 0;
        string label;
        while (*namePart && *namePart != '.') {
            label += *namePart;
            ++namePart;
            ++length;
        }
        if (length > 0) {
            encodedName += length;
            encodedName += label;
        }
        if (*namePart == '.') {
            ++namePart;
        }
    }
    encodedName += '\0'; //null byte
    dnsMessage += encodedName;

    // Add query type and query class
    dnsMessage.append(reinterpret_cast<const char*>(&question.recordType), sizeof(question.recordType));
    dnsMessage.append(reinterpret_cast<const char*>(&question.queryClass), sizeof(question.queryClass));

    // Print the final DNS message as hex
    for (char c : dnsMessage) {
        cout << std::hex << std::setw(2) << setfill('0') << static_cast<int>(static_cast<uint8_t>(c));
    }
    cout << endl;

    // Create a UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    // Server address information
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(53); // DNS service port
    serverAddr.sin_addr.s_addr = inet_addr("8.8.8.8"); // Google DNS server

    // Send the DNS message
    ssize_t sentBytes = sendto(sockfd, dnsMessage.data(), dnsMessage.size(), 0,
                               reinterpret_cast<struct sockaddr*>(&serverAddr),
                               sizeof(serverAddr));

    if (sentBytes == -1) {
        perror("sendkaro");
        close(sockfd);
        return 1;
    }

    // Receive and process response
    char responseBuffer[1024]; // Adjust buffer size if needed
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);
    ssize_t receivedBytes = recvfrom(sockfd, responseBuffer, sizeof(responseBuffer), 0,
                                     reinterpret_cast<struct sockaddr*>(&clientAddr),
                                     &clientAddrLen);
    if (receivedBytes == -1) {
        perror("recvkiya");
        close(sockfd);
        return 1;
    }

    // Process the response data and print it out.
    for (ssize_t i = 0; i < receivedBytes; ++i) {
        cout << hex << setw(2) << setfill('0')
                  << static_cast<int>(static_cast<uint8_t>(responseBuffer[i]));
    }
    cout << std::endl;

    // Close the socket
    close(sockfd);
    return 0;
}
