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

#include "IcmpPacket.h"

int pow(int a, int b){
	int c = a;
	for (; b > 1; --b)
		c *= a;

	return c;
}

IcmpPacket::IcmpPacket(){
	header.type = ICMP_TYPE::ECHO_RQST;
	header.code = 0;
	header.checkSum = 0;
	header.identifier = 1;
	header.sequenceNumber = 1;

	data = "";

	enum_map[ECHO_REPLY] = "ECHO_REPLY";
	enum_map[DST_UNREACHABLE] = "DST_UNREACHABLE";
	enum_map[REDIRECT] = "REDIRECT";
	enum_map[ECHO_RQST] = "ECHO_RQST";
	enum_map[ROUTER_ADV] = "ROUTER_ADV";
	enum_map[ROUTER_SELEC] = "ROUTER_SELEC";
	enum_map[TIME_EXCEEDED] = "TIME_EXCEEDED";
	enum_map[PARAM_PROBLEM] = "PARAM_PROBLEM";
	enum_map[TIMESTAMP] = "TIMESTAMP";
	enum_map[TIMESTAMP_REPLY] = "TIMESTAMP_REPLY";
}

void IcmpPacket::computeChecksum(){
	/*
		According to the RFC 792, the ICMP header checksum is :

		The 16 bit one's complement of the one's complement sum of all 16
      	bit words in the header. For computing the checksum, the checksum
      	field should be zero. This checksum may be replaced in the
      	future.
	*/

	unsigned int dataSum = ((header.type << 8) + header.code) + header.checkSum + header.identifier + header.sequenceNumber;
	unsigned int msgSum = 0;

	for (size_t i = 0; i < data.length(); i += 2){
		msgSum += (static_cast<unsigned char>(data[i]) << 8) + static_cast<unsigned char>(data[i+1]); // Make 16 bit words and do the sum
	}

	std::bitset<32> finalSum = dataSum + msgSum; // 32 bit long to give us some margin
	unsigned char finalSumSize = finalSum.to_string().length() - finalSum.to_string().find('1');

	while (finalSumSize > 16){ // If the final sum is not 16 bit long, we have to add the carry and repeat this process 'til it is 16 bit long
		unsigned int carry = 0;

		for (size_t i = finalSumSize - 1; i > 15; --i){
			if (finalSum[i] == 1){
				carry += pow(2, i - 16);
				finalSum[i] = 0;
			}
		}

		finalSum = finalSum.to_ulong() + carry;
		finalSumSize = finalSum.to_string().length() - finalSum.to_string().find('1');
	}

	finalSum.flip(); // Complements all bit

	header.checkSum = (unsigned short int)(std::bitset<16>(finalSum.to_string().substr(16, 32)).to_ulong()); // Get only first 16 bit
}

std::string IcmpPacket::getPacketInfo(){
	std::stringstream ss;

	ss << "\nType : " << header.type << " (" << enum_map[header.type] << ")";
	ss << "\nCode : " << +header.code;
	ss << "\nChecksum : " << header.checkSum << " (0x" << std::hex << header.checkSum << ")" << std::dec;
	ss << "\nIdentifier : " << header.identifier << " (0x" << std::hex << header.identifier << ")" << std::dec;
	ss << "\nSequence number : " << header.sequenceNumber << " (0x" << std::hex << header.sequenceNumber << ")";
	ss << "\nPayload :" << std::hex;

	if (!data.empty()){
		ss << "\n\nHexa  : ";

		for (size_t i = 0; i < data.length(); ++i){
			ss << static_cast<unsigned int>(data.at(i)) << "  ";
			if ((i+1)%8 == 0 && !(data.length()%8 != 0 && i == data.length()))
				ss << "\n        ";
		}

		ss << "\n\nASCII : ";

		for (size_t i = 0; i < data.length(); ++i){
			if (isprint(data.at(i))){
				ss << data.at(i) << "   ";
			} else {
				ss << ".   ";
			}

			if ((i+1)%8 == 0 && !(data.length()%8 != 0 && i == data.length()))
				ss << "\n        ";
		}
	}

	ss << '\n';
	return ss.str();
}

void IcmpPacket::encodeHeader(unsigned char (&buffer)[8]){
	computeChecksum();

	if (sizeof(buffer) == 8){
		buffer[0] = static_cast<unsigned char>(header.type);
		buffer[1] = static_cast<unsigned char>(header.code);
		buffer[2] = static_cast<unsigned char>(header.checkSum >> 8); //  |--> Cut the 16 bit variable into two 8 bit numbers
		buffer[3] = static_cast<unsigned char>(header.checkSum & 0xFF);// |
		buffer[4] = static_cast<unsigned char>(header.identifier >> 8);
		buffer[5] = static_cast<unsigned char>(header.identifier & 0xFF);
		buffer[6] = static_cast<unsigned char>(header.sequenceNumber >> 8);
		buffer[7] = static_cast<unsigned char>(header.sequenceNumber & 0xFF);
	}
}
