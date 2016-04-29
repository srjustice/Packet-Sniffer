using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace Packet_Sniffer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private decimal numPacketsReceived;
        private bool isCapturing;
        private Socket internetSocket;
        private byte[] byteData = new byte[4096];
        Thread captureThread;
        Dictionary<string, PacketInfo> pkgBuffer = new Dictionary<string, PacketInfo>();
        int maxBufferSize = 1000;

        public MainWindow()
        {
            InitializeComponent();
            Load_Interfaces();
        }

        private void Start_Button_Click(object sender, RoutedEventArgs e)
        {
            //dataGrid.Items.Add(new PacketData { Number = "1", Time_Stamp = "10:00", Source = "Me", Destination = "Me" });

            if (interfaceSelector.Text == "")
            {
                MessageBox.Show("Select an Interface to capture the packets.", "Packet Sniffer",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else if (!isCapturing)
            {
                try
                {
                    Start_Button.Content = "Stop";

                    isCapturing = true;

                    numPacketsReceived = 0;
                    
                    //For sniffing the socket to capture the packets has to be a raw socket, with the
                    //address family being of type internetwork, and protocol being IP
                    internetSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

                    //Bind the socket to the selected IP address
                    internetSocket.Bind(new IPEndPoint(IPAddress.Parse(interfaceSelector.SelectedItem.ToString()), 0));

                    //Set the socket  options
                    internetSocket.SetSocketOption(SocketOptionLevel.IP,            //Applies only to IP packets
                                               SocketOptionName.HeaderIncluded, //Set the include the header
                                               true);                           //option to true

                    byte[] byIn= new byte[4] { 1, 0, 0, 0 };
                    byte[] byOut = new byte[4]; //Capture outgoing packets

                    //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                    internetSocket.IOControl(IOControlCode.ReceiveAll,              //Equivalent to SIO_RCVALL constant
                                                                                //of Winsock 2
                                         byIn,
                                         byOut);

                    //Start receiving the packets asynchronously
                    //internetSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                    //    new AsyncCallback(Packet_Recieved), null);

                    //Capture using a thread
                    captureThread = new Thread(Packet_Recieved);
                    captureThread.Name = "Capture Thread";
                    captureThread.Start();

                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else
            {
                isCapturing = false;
                Start_Button.Content = "Start";

                if (captureThread.IsAlive)
                    captureThread.Abort();

                //To stop capturing the packets close the socket
                internetSocket.Shutdown(SocketShutdown.Both);
                internetSocket.Close();

                numPacketsReceived = 0;
            }
        }

        private void Packet_Recieved()
        {

            while(isCapturing)
            {
                try
                {
                    //int nReceived = internetSocket.EndReceive(receivedPacket);

                    int bytesReceived = internetSocket.Receive(byteData, 0, byteData.Length, SocketFlags.None);

                    //Analyze the bytes received...
                    if (bytesReceived > 0)
                    {
                        ParseData(byteData, bytesReceived);
                    }

                    Array.Clear(byteData, 0, byteData.Length);

                    //ParseData(byteData, bytesReceived);

                    Array.Clear(byteData, 0, byteData.Length);

                    //if (isCapturing)
                    //{
                    //    byteData = new byte[4096];

                    //    //Another call to BeginReceive so that we continue to receive the incoming
                    //    //packets
                    //    internetSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                    //        new AsyncCallback(Packet_Recieved), null);
                    //}
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ParseData(byte[] data, int numReceived)
        {
            if (data.Length > 0 && numReceived != 0)
            {
                //getting IP header and data information
                PacketIP ipPacket = new PacketIP(data, numReceived);

                if (ipPacket.Protocol == "TCP")
                {
                    numPacketsReceived++;

                    // this string used as a key in the buffer
                    string strKey = numPacketsReceived.ToString();

                    PacketTcp tcpPacket = new PacketTcp(ipPacket.Data, ipPacket.MessageLength);

                    //creating new PacketInfo object to fill the buffer
                    PacketInfo pkgInfo = new PacketInfo(ipPacket, tcpPacket);

                    //_pkgBuffer.Add(strKey, pkgInfo);

                    //creating new list item to fill the list view control
                    PacketData packet = new PacketData
                    {
                        Number = numPacketsReceived.ToString(),
                        Time_Stamp = DateTime.Now.ToString("HH:mm:ss:") + DateTime.Now.Millisecond.ToString(),
                        Source = ipPacket.SourceAddress.ToString(),
                        Destination = ipPacket.DestinationAddress.ToString(),
                        Protocol = ipPacket.Protocol,
                        Length = ipPacket.TotalLength//,
                    };
                    //item.SubItems.Add(DateTime.Now.ToString("HH:mm:ss:") + DateTime.Now.Millisecond.ToString());
                    //item.SubItems.Add(ipPacket.SourceAddress.ToString());
                    //item.SubItems.Add(tcpPacket.SourcePort);
                    //item.SubItems.Add(ipPacket.DestinationAddress.ToString());
                    //item.SubItems.Add(tcpPacket.DestinationPort);
                    //item.SubItems.Add(ipPacket.Protocol);
                    //item.SubItems.Add(ipPacket.TotalLength);
                    //item.SubItems.Add(strKey);
                    //dataGrid.Items.Add(new PacketData { Number = "1", Time_Stamp = "10:00", Source = "Me", Destination = "Me" });

                    if (pkgBuffer.Count < maxBufferSize)
                    {
                        pkgBuffer.Add(strKey, pkgInfo);

                        Dispatcher.Invoke((Action)(() =>
                        {
                            dataGrid.Items.Add(packet);
                        }), DispatcherPriority.ContextIdle);
                    }
                }
            }
        }

        private void Load_Interfaces()
        {
            string hostName = Dns.GetHostName();
            IPAddress[] IPs = Dns.GetHostAddresses(hostName);

            foreach (IPAddress ip in IPs)
            {
                interfaceSelector.Items.Add(ip.ToString());
            }
        }

        private void createPacketTree(object sender, SelectionChangedEventArgs e)
        {
            PacketData currentPacket = (PacketData)dataGrid.SelectedItem;

            //getting the number of selected packet which is used as  an key in dictionary
            string index = currentPacket.Number;

            PacketInfo pkgInfo = new PacketInfo();

            //trying to get data with specified key if this data exist 
            //creating a detailed tree
            if (pkgBuffer.TryGetValue(index, out pkgInfo))
            {
                if (pkgInfo.IP.Protocol == "TCP")
                {
                    treeView.Items.Clear();

                    TreeViewItem IPnode = new TreeViewItem();
                    IPnode.Header = "IP";
                    IPnode.Foreground = new SolidColorBrush(Colors.Green);

                    IPnode.Items.Add(new TreeViewItem { Header = "Protocol Version: " + pkgInfo.IP.Version });
                    IPnode.Items.Add(new TreeViewItem { Header = "Header Length: " + pkgInfo.IP.HeaderLength });
                    IPnode.Items.Add(new TreeViewItem { Header = "Type of Service: " + pkgInfo.IP.TypeOfService });
                    IPnode.Items.Add(new TreeViewItem { Header = "Total Length: " + pkgInfo.IP.TotalLength });
                    IPnode.Items.Add(new TreeViewItem { Header = "Identification No: " + pkgInfo.IP.Identification });
                    IPnode.Items.Add(new TreeViewItem { Header = "Flags: " + pkgInfo.IP.Flags });
                    IPnode.Items.Add(new TreeViewItem { Header = "Fragmentation Offset: " + pkgInfo.IP.FragmentationOffset });
                    IPnode.Items.Add(new TreeViewItem { Header = "TTL: " + pkgInfo.IP.TTL });
                    IPnode.Items.Add(new TreeViewItem { Header = "Checksum: " + pkgInfo.IP.Checksum });
                    IPnode.Items.Add(new TreeViewItem
                        { Header = String.Format("Source address: {0}: {1}", pkgInfo.IP.SourceAddress, pkgInfo.TCP.SourcePort) });
                    IPnode.Items.Add(new TreeViewItem
                        { Header = String.Format("Destination address: {0}: {1}", pkgInfo.IP.DestinationAddress, pkgInfo.TCP.DestinationPort) });

                    TreeViewItem TCPnode = new TreeViewItem();
                    TCPnode.Header = "TCP";
                    TCPnode.Foreground = new SolidColorBrush(Colors.Blue);

                    TCPnode.Items.Add(new TreeViewItem { Header = "Sequence No: " + pkgInfo.TCP.SequenceNumber });
                    TCPnode.Items.Add(new TreeViewItem { Header = "Acknowledgement Num: " + pkgInfo.TCP.AcknowledgementNumber });
                    TCPnode.Items.Add(new TreeViewItem { Header = "Header Length: " + pkgInfo.TCP.HeaderLength });
                    TCPnode.Items.Add(new TreeViewItem { Header = "Flags: " + pkgInfo.TCP.Flags });
                    TCPnode.Items.Add(new TreeViewItem { Header = "Window size: " + pkgInfo.TCP.WindowSize });
                    TCPnode.Items.Add(new TreeViewItem { Header = "Checksum: " + pkgInfo.TCP.Checksum });
                    TCPnode.Items.Add(new TreeViewItem { Header = "Message Length: " + pkgInfo.TCP.MessageLength });

                    IPnode.Items.Add(TCPnode);

                    treeView.Items.Add(IPnode);
                }


            }
        }

        public void Show_Bytes(PacketInfo pkgInfo)
        {
            MemberInfo[] IPmembers = typeof(PacketIP).GetMembers();

            foreach(MemberInfo member in IPmembers)
            {
                textBlock.Text = pkgInfo.GetType().GetMember(member.Name).ToString();
            }
        }
    }
}
