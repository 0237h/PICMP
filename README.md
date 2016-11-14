<pre>
						8888888b.     8888888     .d8888b.     888b     d888    8888888b.
						888   Y88b	    888      d88P  Y88b    8888b   d8888    888   Y88b
						888    888      888      888    888    88888b.d88888    888    888
						888   d88P	    888      888           888Y88888P888    888   d88P
						8888888P"	    888      888           888 Y888P 888    8888888P"
						888	            888      888    888    888  Y8P  888    888
						888		        888      Y88b  d88P    888   "   888    888
						888	          8888888     "Y8888P"     888       888    888
</pre>

	                 						Copyright (C) 2016 Krowten11

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

INTRODUCTION :
--------------

* This software is a network scanner who uses the ICMP protocol (https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) to check for live hosts (also known as "ping scanning").

* See *BENCHMARK.txt* for a performance overview of the program.

* Compiled with GCC 4.8.1 and Boost Release 1.62.0 on Windows 7 (64-bits) using the following command line : 
***g++ -Wall -std=c++11 -I"C:\Boost\boost_1_62_0" -L"C:\Boost\boost_1_62_0\lib" *.cpp -o picmp -lboost_regex-mgw48-1_62 -lboost_system-mgw48-1_62 -lboost_iostreams-mgw48-1_62 -lws2_32 -lwsock32***

* Compiled with GCC 5.4.0 and Boost Release 1.52.0 on Ubuntu (32-bits) using the following command line :
***g++ -Wall -std=c++11 -I"/usr/include" -L"/usr/lib/i386-linux-gnu" *.cpp -lboost_system -lboost_regex -lboost_iostreams -o picmp***

DOWNLOADING :
-------------

You can directly download the binaries located in *bin/* or you can compile the source files by yourself (located in *src/*). If you're running Windows, don't forget to download the dll files located in *lib/windows/* and put them beside the *.exe* file.

COMPILING :
-----------

Download the source files located in *src/* and follow the instructions :

<h3>Linux</h3>
- Install GCC and the Boost Library : ***sudo apt-get install gcc*** and ***sudo apt-get install libboost-all-dev***
- Navigate to the folder where the source files are located using the ***cd*** command
- Compile using ***g++ -std=c++11 -I"/usr/include" -L"/usr/lib" *.cpp -o picmp -lboost_system -lboost_regex -lboost_iostreams*** (NB : The include and/or lib directory may change depending if you're on 64 or 32 bits distribution. Use the following command to find where your Boost files are located ***find /usr/include /usr/lib/ -name *boost****)

<h3>Windows</h3>
- Install MinGW (https://sourceforge.net/projects/mingw-w64/) and the Boost Library (https://sourceforge.net/projects/boost/files/boost/)
- Add the path to *g++* executable (*C:/Mingw/bin*) to the PATH environnement variable (google it if you don't know who to do this)
- Open a command prompt : *[Windows Key] + r* -> Type ***cmd*** and hit *Enter*
- Navigate to the folder where the source files are located using the ***cd*** command
- Compile using ***g++ -std=c++11 -I"$BOOST_INSTALL$" -L"$BOOST_INSTALL$\lib" *.cpp -o picmp -lboost_regex-mgw48-1_62 -lboost_system-mgw48-1_62 -lboost_iostreams-mgw48-1_62*** where *$BOOST_INSTALL$* is the path to the Boost Library root folder (if this command fail, try adding ***-lws2_32 -lwsock32*** at the end of the command)
- Copy the *libboost_regex-mgw48-1_62.dll* and *libboost_system-mgw48-1_62.dll* located in *C:\$BOOST_INSTALL$\lib* to your application folder or download it from *lib/windows/*

RUNNING :
---------

This program require to be run from an elevated command prompt :
<h3>Linux</h3>
&nbsp;&nbsp;&nbsp;&nbsp;Change the file permission to executable : ***chmod +x picmp***
<br>&nbsp;&nbsp;&nbsp;&nbsp;Use the ***sudo*** command when you run the program : ***sudo ./picmp***</br>
<h3>Windows</h3>
&nbsp;&nbsp;&nbsp;&nbsp;Press *[Windows Key]* and type ***cmd***. Next, right-click on the *cmd.exe* and choose *run as administrator*. 

Then you have to navigate to the application folder (i.e where the executable is located) using the ***cd*** command.

NB : If you're running Windows, you can also download the *run.bat* file in *bin/windows* and edit it to set the path to the path of your application folder (you also have to run the *run.bat* as administrator).

COMMAND-LINE :
-------------
- ***[Application name]*** : This is the basic command-line to run the program where *[Application name]* is the name of the *.exe* application located in the folder (*picmp* by default). The *default* values (see the *Default Values* array below) will be used for the packet destination.

- ***[Application name] ip*** : This command specifiy the packet's destination. *ip* must be in the standart IPv4 format (x.x.x.x) (IPv6 is not supported yet) and must be in range **[0.0.0.0 - 255.255.255.255]**. You can use ip ranges by using the *'-'* character. For example, using the ip *192.168.1.1-255* the program will scan all ip addresses from *192.168.1.1* to *192.168.1.255*.

OPTIONS :
---------
- ***--help*** : Display all the options availables and what they do.

- ***-data [data]*** or ***-d [data]*** : This option specifiy the data to add at the end of the packet (also known as "payload"). If the payload contains white-space (' '), you must put the entire data in quotes (for example ***-data "Hello World !"***).

- ***-dataFile [fileName]*** or ***-df [fileName]*** : Same as ***-data*** (or ***-d***) except that it reads the payload from a file. *[fileName]* must contains the name of the data file as well as any extension (like *.txt*). The maximum amount of character read by the program is **65507** characters.

- ***-type [type]*** : This option specifiy the ICMP Type of the packet. This option can be set only with one of those values (you must enter the numerical value corresponding to the type that you want) :

|       Type      | Value |
|:---------------:|:-----:|
|    ECHO_REPLY   |   0   |
| DST_UNREACHABLE |   3   |
|     REDIRECT    |   5   |
|    ECHO_RQST    |   8   |
|    ROUTER_ADV   |   9   |
|   ROUTER_SELEC  |   10  |
|  TIME_EXCEEDED  |   11  |
|  PARAM_PROBLEM  |   12  |
|    TIMESTAMP    |   13  |
| TIMESTAMP_REPLY |   14  |

- ***-code [code]*** : This option specifiy the ICMP Code related to the ICMP Type (see http://www.nthelp.com/icmp.html for more details). The value must be in range **[0-15]**.

- ***-id [id]*** : This option specifiy the ICMP Identifier. The value must be in range **[0-65535]**.

- ***-seq [seq]*** : This option specifiy the ICMP Sequence Number. The value must be in range **[0-65535]**.

- ***-count [count]*** or ***-c [count]*** : This option specify the number of packets to send to the target. The value must be in range **[1-65535]** or you can set it to *inf* to continuously send packets to the target. If you set it to *inf*, you can later close the program using *Ctrl + C* or by closing the command prompt.

- ***-timeout [time]*** or ***-t [time]*** : This option specifiy the maximum awaiting time (in millisecond) for the target to respond . The value must be in range **[1-65535]**. 

- ***-verbose*** or ***-v*** : Print more informations about the packets.

- ***-log [fileName]*** : This option create a log file containing all the informations given by the *verbose* output. ***[fileName]*** must be less than 251 characters (cause of the *.txt* extension). You can set the ***[fileName]*** to *default* to let the program define the name of the log file which will be in format *[Day] [Month] [Day in month] [Hours]\_[Minutes]\_[Seconds] [Year]*.

<h3>Example :</h3>
***picmp 192.168.1.1-255 -c 3 -t 100 -log default -d "Just pinging you :D"***

This will ping all hosts from *192.168.1.1* to *192.168.1.255* by sending them **3 packets** (who contains the message **"Just pinging you :D"**) and waiting **100 ms** for the target to respond. All the packets informations will be recorded into a **log file** whose file name is set by the program.

DEFAULT VALUES:
---------------

Here are the default values used by the program :

|       Option      |      Value      |
|:-----------------:|:---------------:|
|         Ip        | 255.255.255.255 |
|        Data       |       NULL      |
|        Type       |        8        |
|        Code       |        0        |
|     Identifier    |        1        |
|  Sequence Number  |        1        |
|       Count       |        4        |
|      Timeout      |       1000      |
 
NB : If a given parameter in the command-line is invalid, he will be ignored (ie. the default value will be used).

CONTACT :
---------

* You can contact me at krowten11[at]gmail[dot]com if you want to share any improvements or ideas about the program.

* Check out the github repo of the project : https://github.com/Krowten11/PICMP

THANKS :
--------

* Thanks to all the Boost Library contributors who made and keep making this library awesome !

* Thanks to the SO Community to help me out when i was going crazy about the code :D

* Thanks to you for checking out my work and help me in my learning. I hope you will share this program to everyone :D

LICENSE :
---------

* Don't forget to check out the license terms available in the *LICENSE* file if you want to use this program for you own work.
