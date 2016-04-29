using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Packet_Sniffer
{
    /// <summary>
    /// This class is designed to carried data 
    /// and place this data in to a buffer 
    /// </summary>
    public class PacketInfo
    {
        PacketIP   _ip;     // IP packet information
        PacketTcp  _tcp;    // TCP header information

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
        public PacketInfo(PacketIP ip, PacketTcp tcp)
        {
            _ip = ip;
            _tcp = tcp;
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
