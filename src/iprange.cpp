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

#include "IpRange.h"

IpRange::IpRange() : IpRange("255.255.255.255"){}

void IpRange::setIpRange(std::string ip){ // Ip format can be a range "A-B" or a value "A"
	unsigned int dot_index = ip.find('.');
	std::string data = ip.substr(0, dot_index); // = Get "A-B" or "A"
	ranges.resize(4);

	for (size_t i = 0; i < 4; ++i){
		if (data.find('-') != std::string::npos){ // If == "A-B"
			unsigned int firstValue = boost::lexical_cast<unsigned int>(data.substr(0, data.find('-')));
			unsigned int secondValue = boost::lexical_cast<unsigned int>(data.substr(data.find('-') + 1, (data.length() - data.find('-'))));

			if (!(0 < firstValue && firstValue < 256 && 0 < secondValue && secondValue < 256)){ // Out of range [0-255]
				setIpRange("255.255.255.255");
				return;
			}

			if (firstValue > secondValue)
				std::swap(firstValue, secondValue);

			ranges[i].min = firstValue;
			ranges[i].max = secondValue;
			ranges[i].current = firstValue;
			ranges[i].isNotRange = false;
		} else { // If == "A"
			ranges[i].isNotRange = true;
			ranges[i].current = boost::lexical_cast<unsigned int>(data);
		}
		// Updating position
		unsigned int old_index = dot_index;
		dot_index = ip.find('.', dot_index + 1);
		data = ip.substr(old_index + 1, dot_index - old_index - 1);
	}
}

std::string IpRange::getCurrentIp(){
	std::stringstream ss;
	ss << ranges[0].current << '.' << ranges[1].current << '.' << ranges[2].current << '.' << ranges[3].current;
	return ss.str();
}

void IpRange::updateFirst(){
	if (!ranges[3].isNotRange){
		if (++(ranges[3].current) > ranges[3].max){
			ranges[3].current = ranges[3].min;
			updateSecond(); // We reached the max and we update the next one
		}
	} else {
		updateSecond(); // This one is a constant value so we update the next one
	}
}

void IpRange::updateSecond(){
	if (!ranges[2].isNotRange){
		if (++(ranges[2].current) > ranges[2].max){
			ranges[2].current = ranges[2].min;
			updateThird();
		}
	} else {
		updateThird();
	}
}

void IpRange::updateThird(){
	if (!ranges[1].isNotRange){
		if (++(ranges[1].current) > ranges[1].max){
			ranges[1].current = ranges[1].min;
			updateFourth();
		}
	} else {
		updateFourth();
	}
}

void IpRange::updateFourth(){
	if (!ranges[0].isNotRange){
		if (++(ranges[0].current) > ranges[0].max){
			ranges[0].current = ranges[0].max;
			max_reached = true;
		}
	} else {
		max_reached = true;
	}
}