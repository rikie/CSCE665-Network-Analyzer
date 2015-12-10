# CSCE665-Network-Analyzer
A CPP program to reassemble network packets

This program has been compiled, run and tested on UBUNTU 14.04 LTS system

To RUN this program:

1.	Install flex, bison, gcc and g++.
    Make sure that gcc, flex and bison are installed. 
    You can do a sudo apt-get install gcc flex bison to install them if not already installed.
  
2.	Install libpcap library from http://www.tcpdump.org/release/libpcap-0.9.4.tar.gz
    To install that library, just uncompress and untar that
    and install via - ./configure, make, make install

3.	To compile run the following command from the directory where you have the source code.
    This mst be done after the pre-requs in 
    # g++ -std=c++11 networkAnalyzer.cpp -o networkAnalyzer  -lpcap
    
4.	To run the program: ./networkAnalyzer tfsession.pcap
    Where tfsession.pcap is the file where you have captured network packets and you want to analyze those.

References: 

http://www.tcpdump.org/pcap.html
http://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c
http://www.tcpdump.org/sniffex.c
http://packetlife.net/blog/2010/jun/7/understanding-tcp-sequence-acknowledgment-numbers/
