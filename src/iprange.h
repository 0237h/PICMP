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

#ifndef IP_RANGE_H
#define IP_RANGE_H

#include <string>
#include <utility>
#include <vector>
#include <sstream>

#include <boost/lexical_cast.hpp>

class IpRange {
public:
	IpRange();
	IpRange(std::string ip){setIpRange(ip);};

	void setIpRange(std::string ip);
	std::string getCurrentIp();
	void update() {updateFirst();}
	bool maxReached() const {return max_reached;}

private:
	struct Range {
		unsigned int min = 0;
		unsigned int max = 255;
		unsigned int current = min;

		bool isNotRange = false;
	};
	
	bool max_reached = false;
	std::vector<Range> ranges;

	void updateFirst();
	void updateSecond();
	void updateThird();
	void updateFourth();
};

#endif