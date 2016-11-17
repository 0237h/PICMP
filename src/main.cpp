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

#include "icmppacket.h"
#include "iprange.h"
#include "includes.h"

enum class VERBOSE_STREAM_DST {CONSOLE, FILE, BOTH, NONE};

void printHello(){
	std::cout << "\n       8888888b.   8888888     .d8888b.     888b     d888    8888888b.\n"
			  << "       888   Y88b    888      d88P  Y88b    8888b   d8888    888   Y88b\n"
			  << "       888    888    888      888    888    88888b.d88888    888    888\n"
			  << "       888   d88P    888      888           888Y88888P888    888   d88P\n"
			  << "       8888888P      888      888           888 Y888P 888    8888888P\"\n"
			  << "       888           888      888    888    888  Y8P  888    888\n"
			  << "       888           888      Y88b  d88P    888   \"   888    888\n"
			  << "       888         8888888     \"Y8888P\"     888       888    888\n\n"
			  << "                          Copyright (C) 2016 Krowten11\n"
    		  << "                This program comes with ABSOLUTELY NO WARRANTY.\n"
    		  << "        This is a free software, and you are welcome to redistribute it\n"
    		  << "         under certain conditions. See \"LICENSE.txt\" for more details.\n";
}

void displayHelp(){
	std::cout << "\nUsage : picmp [options] target_ip\n\nOptions :\n\n"
			  << "   target_ip                      Target(s) ip. You can use ip ranges with\n                                  the '-' character. Ex : 192.168.1.1-255\n\n"
			  << "   -data or -d [payload]          Payload to send within the packet. If it\n                                  contains white-space, you must put it in\n                                  between quotes.\n\n"
			  << "   -dataFile or -df [file name]   Same as -data (or -d) except that it reads\n                                  the payload from a file.\n\n"
			  << "   -type [type]                   ICMP type of the packet. See \"README.txt\" to\n                                  find the associate code type.\n\n"
			  << "   -code [code]                   ICMP code of the packet.\n\n"
			  << "   -id [identifier]               Identifier of the packet. Value must be in\n                                  range [0-65535].\n\n"
			  << "   -seq [sequence number]         Sequence number of the packet. Value must\n                                  be in range [0-65535].\n\n"
			  << "   -count or -c [count]           Number of packet to send to the target.\n                                  Value must be in range [1-65535] or set\n                                  to \"inf\" to send packets continuously.\n\n"
			  << "   -timeout or -t [timeout]       Maximum awaiting time (in milliseconds) for\n                                  the target to respond. Value must be in range\n                                  [1-65535].\n\n"
			  << "   -verbose or -v                 Enable verbose output and print a lot more\n                                  informations about the packets.\n\n"
			  << "   -log [file name]               Create log file containing all informations\n                                  given by the verbose output. File name must\n                                  be less than 252 characters. You can set this\n                                  option to \"default\" to let the program choose\n                                  the file name.\n\n"
			  << "   --help                         Display this help page.\n";
}

void timerHandler(const boost::system::error_code& e, boost::asio::ip::icmp::socket &socket, VERBOSE_STREAM_DST verbose_dst, 
				  std::stringstream &verbose_ss){
	if (!e){
		if (verbose_dst != VERBOSE_STREAM_DST::NONE)
			verbose_ss << "\nTimeout !\n";
		socket.cancel();
	}
}

void receiveHandler(size_t receivedBytes, boost::asio::ip::icmp::endpoint &target, boost::asio::deadline_timer &timer, 
					boost::asio::streambuf &receive, unsigned int &packetReceived, VERBOSE_STREAM_DST verbose_dst, 
					std::stringstream &verbose_ss){
	if (receivedBytes != 0){
		timer.cancel();
		receive.commit(receivedBytes);

		std::istream is(&receive);
		unsigned char data[8];

		// +--------------------------------------------------------------------------------+
		// |----------------------------- Extracting IP Header -----------------------------|
		// +--------------------------------------------------------------------------------+
		is.ignore(12); // Ignore beginning of IP header
		unsigned char ip_src_header[4];
		is.read(reinterpret_cast<char*>(ip_src_header), 4);

		boost::asio::ip::address_v4::bytes_type bytes = {ip_src_header[0], ip_src_header[1], ip_src_header[2], ip_src_header[3]};
		boost::asio::ip::icmp::endpoint src;
		src.address(boost::asio::ip::address_v4(bytes)); // Get source ip

		is.ignore(4); // Ignore destination ip (us)

		if (src.address() == target.address()){ // If the reply comes from the target
			// +----------------------------------------------------------------------------------+
			// |----------------------------- Extracting ICMP Header -----------------------------|
			// +----------------------------------------------------------------------------------+
			is.read(reinterpret_cast<char*>(data), 8);

			if (is.gcount() == 8){
				IcmpPacket reply;
					reply.type((ICMP_TYPE)(static_cast<unsigned int>(data[0])));
					reply.code(static_cast<unsigned char>(data[1]));
					reply.checkSum(static_cast<unsigned short int>((data[2] << 8) + data[3]));
					reply.identifier(static_cast<unsigned short int>((data[4] << 8) + data[5]));
					reply.sequenceNumber(static_cast<unsigned short int>((data[6] << 8) + data[7]));
				// +-----------------------------------------------------------------------------------+
				// |----------------------------- Extracting ICMP Payload -----------------------------|
				// +-----------------------------------------------------------------------------------+
				char payload[receivedBytes - 28];
				is.read(payload, receivedBytes - 28);

				if (is.gcount() != 0)
					reply.payload(payload);
				
				if (verbose_dst != VERBOSE_STREAM_DST::NONE){
					verbose_ss << "\nResponse\n--------";
					verbose_ss << reply.getPacketInfo();
				}

				if (reply.type() == ECHO_REPLY) // Host is up
					++packetReceived;
			} else {
				std::cout << "Could not read the packet header.\n";
			}
		}
	}
}

void appendToLogFile(std::string data, std::string fileName){
	std::ofstream ofs(fileName, std::ofstream::app);

	if (ofs){
		ofs << data;
		ofs.close();
	} else {
		std::cout << "\nCould not create or append to log file\n";
	}
}

void appendToTopOfFile(std::string data, std::string fileName){
	std::ifstream ifs(fileName);

	if (ifs){
		std::stringstream ss;
		ss << ifs.rdbuf();
		ifs.close();

    	std::ofstream ofs("tmp.txt", std::ofstream::app);

    	if (ofs){
    		ofs << data << ss.str();
    		ofs.close();

    		std::remove(fileName.c_str());
    		std::rename("tmp.txt", fileName.c_str());
    	} else {
    		std::cout << "\nCould not create / append temp file\n";
    	}
	} else {
		std::cout << "\nCould not read log file\n";
	}
}

int main(int argc, char** argv){
	std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
	IcmpPacket packet;
	std::string dst_ip = boost::asio::ip::address_v4::broadcast().to_string();

	bool ip_range_set = false;
	IpRange ip_ranges;

	VERBOSE_STREAM_DST verbose_dst = VERBOSE_STREAM_DST::NONE;
	std::string fileName = "";

	unsigned int timeout = 1000;
	unsigned int count = 4;
	bool inf_count = false;

	unsigned int host_alive = 0;
	unsigned int host_scan = 0;
	
	// +----------------------------------------------------------------------------------+
	// |----------------------------- Command line arguments -----------------------------|
	// +----------------------------------------------------------------------------------+
	{
		const boost::regex ip_regex("^\\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|$)){4}\\b$");
		const boost::regex ip_range_regex("^(\\d+(-\\d*)?\\.){3}(\\d+(-\\d*)?)$");
		const boost::regex data_regex("^((-data=)|(-d=)){1}.+$");
		const boost::regex type_regex("^(0|3|5|8|9|10|11|12|13|14){1}$");
		const boost::regex code_regex("^([0-9]|10|11|12|13|14|15){1}$");
		const boost::regex num_regex("^\\d+$");
		const boost::regex count_regex("^((\\d+)|inf)$");

		std::vector<bool> args_set = {false};
		args_set.resize(10);

		if (argc > 1){
			for (int i = 1; i < argc; ++i){
				std::string tmp(argv[i]);
				std::string data = "";

				if (regex_match(tmp, ip_regex) && !args_set[0]){
					dst_ip = tmp;
					args_set[0] = true;
				} else if (regex_match(tmp, ip_range_regex) && !ip_range_set){
					ip_ranges.setIpRange(tmp);
					ip_range_set = true;
					dst_ip = ip_ranges.getCurrentIp();
				} else if ((tmp == "-data" || tmp == "-d") && !args_set[1]){
					data = argv[i + 1];
					packet.payload(data);
					args_set[1] = true;
				} else if ((tmp == "-dataFile" || tmp == "-df") && !args_set[2]){
					data = argv[i + 1];
					std::ifstream f(data);
					if(f){
						std::stringstream ss;
						ss << f.rdbuf();
						f.close();
						std::string tmp = ss.str();
						if (tmp.length() > 65507)
							tmp.erase(tmp.length() - (tmp.length() - 65507), tmp.length());
						packet.payload(tmp);
						args_set[2] = true;
					}
				} else if (tmp == "-type" && !args_set[3]){
					data = argv[i + 1];
					if (regex_match(data, type_regex)){
						packet.type((ICMP_TYPE)(boost::lexical_cast<unsigned int>(data)));
						args_set[3] = true;
					}
				} else if (tmp == "-code" && !args_set[4]){
					data = argv[i + 1];
					if (regex_match(data, code_regex)){
						packet.code(boost::lexical_cast<unsigned int>(data));
						args_set[4] = true;
					}
				} else if (tmp == "-id" && !args_set[5]){
					data = argv[i + 1];
					if (regex_match(data, num_regex)){
						unsigned int value = boost::lexical_cast<unsigned int>(data);
						if (0 <= value && value < std::numeric_limits<unsigned int>::max()){
							packet.identifier(boost::lexical_cast<unsigned int>(data));
							args_set[5] = true;
						}
					}
				} else if (tmp == "-seq" && !args_set[6]){
					data = argv[i + 1];
					if (regex_match(data, num_regex)){
						unsigned int value = boost::lexical_cast<unsigned int>(data);
						if (0 <= value && value < std::numeric_limits<unsigned int>::max()){
							packet.sequenceNumber(boost::lexical_cast<unsigned int>(data));
							args_set[6] = true;
						}
					}
				} else if ((tmp == "-verbose" || tmp == "-v") && !args_set[7]){
					if (verbose_dst == VERBOSE_STREAM_DST::FILE)
						verbose_dst = VERBOSE_STREAM_DST::BOTH;
					else
						verbose_dst = VERBOSE_STREAM_DST::CONSOLE;
					args_set[7] = true;
				} else if ((tmp == "-timeout" || tmp == "-t") && !args_set[8]){
					data = argv[i + 1];
					if (regex_match(data, num_regex)){
						unsigned int value = boost::lexical_cast<unsigned int>(data);
						if (0 < value && value < std::numeric_limits<unsigned int>::max()){
							timeout = boost::lexical_cast<unsigned int>(data);
							args_set[8] = true;
						}
					}
				} else if ((tmp == "-count" || tmp == "-c") && !args_set[9]){
					data = argv[i + 1];
					if (regex_match(data, count_regex)){
						if (data != "inf"){
							unsigned int value = boost::lexical_cast<unsigned int>(data);
							if (0 < value && value < std::numeric_limits<unsigned int>::max()){
								count = boost::lexical_cast<unsigned int>(data);
								args_set[9] = true;
							}
						} else {
							inf_count = true;
							args_set[9] = true;
						}
					}
				} else if (tmp == "-log" && !args_set[10]){
					if (verbose_dst == VERBOSE_STREAM_DST::CONSOLE)
						verbose_dst = VERBOSE_STREAM_DST::BOTH;
					else
						verbose_dst = VERBOSE_STREAM_DST::FILE;
					data = argv[i + 1];

					if (0 < data.length() && data.length() < 252){
						if (data == "default"){
							std::time_t tmp_time = std::chrono::system_clock::to_time_t(t1);
							fileName = std::ctime(&tmp_time);
							fileName.pop_back();
							std::replace(fileName.begin(), fileName.end(), ':', '_');
							fileName.append(".txt");
						} else { 
							fileName = data + ".txt";
						}

						args_set[10] = true;
						std::ifstream f(fileName);
						if(f){
							f.close();
							std::remove(fileName.c_str());
						}
					}
				} else if (tmp == "--help"){
					displayHelp();
					exit(EXIT_SUCCESS);
				}
			}
		}
	}

	printHello();
	// +----------------------------------------------------------------------------+
	// |----------------------------- Preparing packet -----------------------------|
	// +----------------------------------------------------------------------------+
	boost::asio::io_service io;
	boost::asio::ip::icmp::endpoint target;
	boost::asio::ip::icmp::socket socket(io, boost::asio::ip::icmp::v4());
		socket.set_option(boost::asio::socket_base::broadcast(true));
		socket.set_option(boost::asio::socket_base::send_buffer_size(65536));

	unsigned char header[8];
	packet.encodeHeader(header);

	// +--------------------------------------------------------------------------+
	// |----------------------------- Wraping packet -----------------------------|
	// +--------------------------------------------------------------------------+
	boost::asio::streambuf buff;
	std::ostream os(&buff);
		os.write(reinterpret_cast<const char*>(header), 8);
		os.write(reinterpret_cast<const char*>(packet.payload().c_str()), packet.payload().length());

	do {
		std::stringstream verbose_ss;
		// +---------------------------------------------------------------------------------------+
		// |----------------------------- Updating packet destination -----------------------------|
		// +---------------------------------------------------------------------------------------+
		target.address(boost::asio::ip::address::from_string(dst_ip));

		if (verbose_dst != VERBOSE_STREAM_DST::NONE){
			verbose_ss << "\n-----------------------------------------------\n\n" << count << " packet(s) send to " << dst_ip << '\n';
			verbose_ss << packet.getPacketInfo();
		}

		unsigned int packetReceived = 0;
		unsigned int tmp_count = count;

		do {
			// +--------------------------------------------------------------------------+
			// |----------------------------- Sending packet -----------------------------|
			// +--------------------------------------------------------------------------+
			unsigned int bytesSend = socket.send_to(buff.data(), target);
			
			if (bytesSend == 0){
				if (verbose_dst != VERBOSE_STREAM_DST::NONE)
					verbose_ss << "\nFailed to send the packet :(\nPlease check that the ip address is correct.";
			} else {
				if (verbose_dst != VERBOSE_STREAM_DST::NONE)
					verbose_ss << "\nBytes send : " << std::dec << bytesSend - 8 << " data (+ 8 header = " << bytesSend << ").\n";
				// +----------------------------------------------------------------------------+
				// |----------------------------- Async operations -----------------------------|
				// +----------------------------------------------------------------------------+
				io.reset();
				boost::asio::deadline_timer timer(io, boost::posix_time::milliseconds(timeout));
				timer.async_wait(boost::bind(timerHandler, boost::asio::placeholders::error, boost::ref(socket), verbose_dst, 
								 boost::ref(verbose_ss)));

				boost::asio::streambuf receive;
				
				socket.async_receive(receive.prepare(65535), boost::bind(receiveHandler, boost::asio::placeholders::bytes_transferred, 
									 boost::ref(target), boost::ref(timer), boost::ref(receive), boost::ref(packetReceived),
									 verbose_dst, boost::ref(verbose_ss)));
				io.run();
			}

			if (!inf_count)
				--tmp_count;
		} while (inf_count || tmp_count > 0); // Sending packets according to "-count" option
		// +---------------------------------------------------------------------------------+
		// |----------------------------- Verbose option output -----------------------------|
		// +---------------------------------------------------------------------------------+
		if (verbose_dst != VERBOSE_STREAM_DST::NONE){
			if (verbose_dst == VERBOSE_STREAM_DST::CONSOLE || verbose_dst == VERBOSE_STREAM_DST::BOTH)
				std::cout << verbose_ss.str();
			if (verbose_dst == VERBOSE_STREAM_DST::FILE || verbose_dst == VERBOSE_STREAM_DST::BOTH)
				appendToLogFile(verbose_ss.str(), fileName);
		}

		std::stringstream host_ss;

		if (verbose_dst == VERBOSE_STREAM_DST::NONE && ip_range_set && packetReceived)
			host_ss << '\n';

		if (!ip_range_set && !packetReceived){
			host_ss << "\nHost (" << dst_ip << ") seems to be dead. ";				
		} else if (packetReceived){
			host_ss << "\nHost (" << dst_ip << ") is up ! ";
			++host_alive;
		}
		
		if ((packetReceived && ip_range_set) || !ip_range_set)
			host_ss << std::dec << packetReceived << " / " << count << " replies ("<< (int)(100 - (((float)packetReceived / (float)count)*100)) << " \% loss).\n";
		
		std::cout << host_ss.str();

		if (verbose_dst == VERBOSE_STREAM_DST::FILE || verbose_dst == VERBOSE_STREAM_DST::BOTH){
		 	appendToLogFile(host_ss.str(), fileName);
		}
		// +-------------------------------------------------------------------------------------------------------+
		// |----------------------------- Updating ip address if we are using a range -----------------------------|
		// +-------------------------------------------------------------------------------------------------------+
		if (ip_range_set){ 
			ip_ranges.update();
			dst_ip = ip_ranges.getCurrentIp();
			ip_range_set = !(ip_ranges.maxReached());
		}

		++host_scan;
	} while (ip_range_set); // Ip ranges loop

	std::stringstream result_ss;
	result_ss << "\n-----------------------------------------------\n\nScan finished in " 
			  << std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - t1 ).count() <<"s.\n" 
			  << host_alive << " host(s) alive(s) (out of " << host_scan << " hosts scan).\n";
	std::cout << result_ss.str();

	if (verbose_dst == VERBOSE_STREAM_DST::FILE || verbose_dst == VERBOSE_STREAM_DST::BOTH){
	 	std::cout << "Log file created : " << fileName << '\n';
	 	appendToTopOfFile(result_ss.str(), fileName);
	}
	
	std::cout << "\nPress any key and hit enter to close the program : ";
	std::cin >> host_scan;

	return 0;
}