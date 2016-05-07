using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

//This class was obtained from Sergej Kuznecov at http://www.coderbag.com/Programming-C/Building-a-Network-Sniffer-in-NET.

namespace Packet_Sniffer
{
    /// <summary>
    /// This class is designed to carried data 
    /// and place this data in to a buffer 
    /// </summary>
    public class PacketInfo
    {
        private PacketIP   _ip;     // IP packet information
        private PacketTcp  _tcp;    // TCP header information
        public string packetHex { get; set; }   //Packet data in hex
        public string packetAscii { get; set; }  //Packet data in Ascii

        /// <summary>
        /// 
        /// Some overloaded constructors 
        /// they may teke any of packets combination 
        /// ECSAMPLE: if IP packet contains TCP protocol and data using ->PacketInfo(IPData ip,TCPData tcp)
        /// 
        /// </summary>
        /// 
        public PacketInfo()
        {
        }
        public PacketInfo(PacketIP ip)
        {
            _ip = ip;
        }
        public PacketInfo(PacketIP ip, PacketTcp tcp, string hex, string ascii)
        {
            _ip = ip;
            _tcp = tcp;
            packetHex = hex;
            packetAscii = ascii;
        }

        public PacketIP IP
        {
            get { return _ip; }
        }
        public PacketTcp TCP
        {
            get { return _tcp; }
        }
    }
}
