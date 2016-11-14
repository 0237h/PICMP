/*
Copyright (C) 2016 Krowten11

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef ICMP_PACKET_H
#define ICMP_PACKET_H

#include <iostream>
#include <string>
#include <bitset>
#include <array>
#include <sstream>

#include <cmath>
#include <cctype>

#define _WIN32_WINNT 0x0501

#include <boost/asio.hpp>
#include <boost/regex.hpp>

//						      ICMP PACKET
//						      -----------
//
// 0               8               16                             31
// +---------------+---------------+------------------------------+      ---
// |               |               |                              |       ^
// |     type      |     code      |          checksum            |       |
// |               |               |                              |       |
// +---------------+---------------+------------------------------+    8 bytes
// |                               |                              |       |
// |          identifier           |       sequence number        |       |
// |                               |                              |       v
// +-------------------------------+------------------------------+      ---
// |                                                              |
// |                            Payload                           |
// |                                                              |
// +-------------------------------+------------------------------+

enum ICMP_TYPE {ECHO_REPLY = 0, DST_UNREACHABLE = 3, REDIRECT = 5, ECHO_RQST = 8, ROUTER_ADV = 9, ROUTER_SELEC = 10, TIME_EXCEEDED = 11, 
				PARAM_PROBLEM = 12, TIMESTAMP = 13, TIMESTAMP_REPLY = 14};

class IcmpPacket {

public:
	IcmpPacket();

	void encodeHeader(unsigned char (&buffer)[8]);
	std::string getPacketInfo();

	std::string payload() const {return data;}
	void payload(std::string newData) {data = newData;}

	ICMP_TYPE type() const {return header.type;}
	void type(ICMP_TYPE type) {header.type = type;}

	unsigned char code() const {return header.code;}
	void code(unsigned char code) {if (code < 16)header.code = code;}

	unsigned short int identifier() const {return header.identifier;}
	void identifier(unsigned short int identifier) {header.identifier = identifier;}

	unsigned short int sequenceNumber() const {return header.sequenceNumber;}
	void sequenceNumber(unsigned short int sequenceNumber) {header.sequenceNumber = sequenceNumber;}

	unsigned short int checkSum() const {return header.checkSum;}
	void checkSum(unsigned short int checkSum) {header.checkSum = checkSum;}
private:
	std::string data;

	struct Header {
		ICMP_TYPE type;
		unsigned char code;
		unsigned short int checkSum;
		unsigned short int identifier;
		unsigned short int sequenceNumber;
	} header;

	std::array<std::string, 15> enum_map; 

	void computeChecksum();
};

#endif
