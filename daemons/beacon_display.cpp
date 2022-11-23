/*
 * Marcel - UFRRJ - 2022
 *
 * compilar: g++ -o beacon_display beacon_display.cpp -std=c++17 -ltins
 */

#include "date.h"
#include <iostream>
#include <fstream>
#include <set>
#include <string>
#include <tins/tins.h>
#include <chrono>

using std::set;
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::runtime_error;
using namespace std::chrono;
using namespace date;
using namespace Tins;
 
std::ofstream out;

bool callback(const Packet& packet) {
	const PDU* pdu = packet.pdu();
    const RadioTap& radiotap = pdu->rfind_pdu<RadioTap>();
    const Dot11Beacon& beacon = pdu->rfind_pdu<Dot11Beacon>();

	Timestamp ts = packet.timestamp();
	std::chrono::microseconds us = ts;

	cerr << sys_time<microseconds>{microseconds(us.count())} << "," << beacon.addr2() << "," << (int)radiotap.dbm_signal() << "\n";
	out << sys_time<microseconds>{microseconds(us.count())} << "," << beacon.addr2() << "," << (int)radiotap.dbm_signal() << "\n";
	out.flush();

    return true;
}
 
int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " <<* argv << " <interface> <outputfile> <space sep list of macs>" << endl;
        return 1;
    }

	// parse args
    string iface = argv[1];
    out.open (argv[2]);
	string mac_filter = "";
	for (int i=3; i < argc; i++) {
			mac_filter = mac_filter + argv[i];
			if (i != (argc-1)) 
					mac_filter = mac_filter + " or ";
	}
	//cout << "subtype beacon and wlan addr2 " + mac_filter << "\n";

    SnifferConfiguration config;
    config.set_promisc_mode(true);
	if (!mac_filter.empty())
			config.set_filter("subtype beacon and wlan addr2 " + mac_filter);
	else
			config.set_filter("subtype beacon");
	config.set_rfmon(true);

    Sniffer sniffer(iface, config);
    
	sniffer.sniff_loop(callback);
	
	out.close();

}
