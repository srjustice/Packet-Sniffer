using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;

//This class was obtained from Sergej Kuznecov at http://www.coderbag.com/Programming-C/Building-a-Network-Sniffer-in-NET.

namespace Packet_Sniffer
{
    public class PacketTcp
    {
         /// <summary>
        ///  TCP header structure
        /// 
        /// IETF RFC793 defines the Transmission Control Protocol (TCP). 
        /// TCP provides a reliable stream delivery and virtual connection service 
        /// to applications through the use of sequenced acknowledgment with 
        /// retransmission of packets when necessary.
        /// 
        /// </summary>
        /// 
        public ushort _usSourcePort { get; set; }          //16 bits for source port         
        public ushort _usDestinationPort { get; set; }     //16 bits for destination port   
        public uint   _uiSequenceNumber { get; set; }      //32 bits for sequence number   
        public uint   _uiAckNumber { get; set; }           //32 bits for acknowledgement number
        public ushort _usDataOffsetAndFlags { get; set; }  //16 bits for data offset and flags  
        public ushort _usWindow { get; set; }              //16 bits for window size   
        public short  _sChecksum { get; set; }             //16 bits for checksum

        public ushort _usUrgentPointer { get; set; }       //16 bits for urgent pointer    

        public byte   _bHeaderLength { get; set; }               //8 bits for TCP header length   
        public ushort _usMessageLength { get; set; }             // data length carried by TCP packet    
        private byte[] _bTCPData = new byte[4096];  // buffer for data carried by TCP packet
       
        public PacketTcp(byte [] bBuffer, int iReceived)
        {
                // Preparing to read data from buffer (creating stream objects)
                MemoryStream memoryStream = null;
                BinaryReader binaryReader = null;

                try
                {
                    memoryStream = new MemoryStream(bBuffer, 0, iReceived);
                    binaryReader = new BinaryReader(memoryStream);

                    // first 16 bits for source port 
                    // NetworkToHostOrder() this method converts a value from host byte order to network byte order
                    _usSourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                    // 16 bits for destination port
                    _usDestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                    // next 32 bits represent sequence number
                    _uiSequenceNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

                    // 32 bits for acknowledgement number
                    _uiAckNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

                    // 16 bits for offset and flags (flags 8 bits and 8 bits for data offset
                    _usDataOffsetAndFlags = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                    // 16 bits for window size
                    _usWindow = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                    // 16 bits for checksum
                    _sChecksum = (short)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                    //16 bits for urgentpoint
                    _usUrgentPointer = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                    // counting length of TCP header
                    _bHeaderLength = (byte)(_usDataOffsetAndFlags >> 12);
                    _bHeaderLength *= 4;

                    // counting length of data carried by TCP packet
                    _usMessageLength = (ushort)(iReceived - _bHeaderLength);

                    //copying data carried by TCP packet in to buffer
                    Array.Copy(bBuffer, _bHeaderLength, _bTCPData, 0, iReceived - _bHeaderLength);
                }
                catch (Exception) { }

                finally
                {
                    binaryReader.Close();
                    memoryStream.Close();
                }
        }

        public string SourcePort
        {
            get { return _usSourcePort.ToString(); }
        }

        public string DestinationPort
        {
            get { return _usDestinationPort.ToString(); }
        }

        public string SequenceNumber
        {
            get { return _uiSequenceNumber.ToString(); }
        }

        public string AcknowledgementNumber
        {
            get
            {
                if ((_usDataOffsetAndFlags & 0x10) != 0)
                    return _uiAckNumber.ToString();
                else
                    return "";
            }
        }

        public string HeaderLength
        {
            get { return _bHeaderLength.ToString(); }
        }

        public string WindowSize
        {
            get { return _usWindow.ToString(); }
        }

        public string UrgentPointer
        {
            get
            {
                if ((_usDataOffsetAndFlags & 0x20) != 0)
                    return _usUrgentPointer.ToString();
                else
                    return "";
            }
        }

        public string Flags
        {
            get
            {
                int iFlags = _usDataOffsetAndFlags & 0x3F;
 
                string strFlags = string.Format ("0x{0:x2} ", iFlags);

                if ((iFlags & 0x01) != 0)
                    strFlags += "FIN  ";

                if ((iFlags & 0x02) != 0)
                    strFlags += "SYN  ";

                if ((iFlags & 0x04) != 0)
                    strFlags += "RST  ";

                if ((iFlags & 0x08) != 0)
                    strFlags += "PSH  ";

                if ((iFlags & 0x10) != 0)
                    strFlags += "ACK  ";

                if ((iFlags & 0x20) != 0)
                    strFlags += "URG ";

                if (strFlags.Contains("()"))
                    strFlags = strFlags.Remove(strFlags.Length - 3);

                else if (strFlags.Contains(", )"))
                    strFlags = strFlags.Remove(strFlags.Length - 3, 2);

                return strFlags;
            }
        }

        public string Checksum
        {
            get { return "0x" + _sChecksum.ToString("x"); }
        }

        public byte[] Data
        {
            get { return _bTCPData; }
        }

        public string MessageLength
        {
            get { return _usMessageLength.ToString(); }
        }
    }
}
