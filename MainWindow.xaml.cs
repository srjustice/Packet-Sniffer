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
        int maxBufferSize;
        bool showAscii = true;      //true for Ascii, false for Hex


        public MainWindow()
        {
            InitializeComponent();
            Load_Interfaces();
            Set_Icon();
        }

        private void Start_Button_Click(object sender, RoutedEventArgs e)
        {

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
                    Start_Button.Background = Brushes.Red;

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

                    byte[] byIn = new byte[4] { 1, 0, 0, 0 };
                    byte[] byOut = new byte[4] { 1, 0, 0, 0 }; //Capture outgoing packets

                    //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                    internetSocket.IOControl(IOControlCode.ReceiveAll,              //Equivalent to SIO_RCVALL constant
                                                                                    //of Winsock 2
                                         byIn,
                                         byOut);

                    //Start receiving the packets asynchronously
                    //internetSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                    //new AsyncCallback(Packet_Recieved), null);

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
                Start_Button.Background = Brushes.LimeGreen;

                if (captureThread.IsAlive)
                    captureThread.Abort();

                //To stop capturing the packets close the socket
                internetSocket.Shutdown(SocketShutdown.Both);
                internetSocket.Close();
            }
        }

        private void Packet_Recieved()//IAsyncResult receivedPacket)
        {

            while (isCapturing)
            {
                try
                {
                    int bytesReceived = internetSocket.Receive(byteData, 0, byteData.Length, SocketFlags.None);

                    //Analyze the bytes received...
                    if (bytesReceived > 0)
                    {
                        ParseData(byteData, bytesReceived);
                    }

                    Array.Clear(byteData, 0, byteData.Length);
                }

                /* try
                 {
                     int bytesReceived = internetSocket.EndReceive(receivedPacket);

                     //Analyze the bytes received...
                     if (bytesReceived > 0)
                     {
                         ParseData(byteData, bytesReceived);
                     }

                     if (isCapturing)
                     {
                         Array.Clear(byteData, 0, byteData.Length);

                         internetSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                              new AsyncCallback(Packet_Recieved), null);
                     }
                 }*/
                catch (ObjectDisposedException ex)
                {
                    Console.WriteLine(ex.Message);
                }
                catch (Exception ex)
                {
                    //MessageBox.Show(ex.Message, "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Error);

                    Console.Write(ex.Message + "\r\n");

                    //internetSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                    //new AsyncCallback(Packet_Recieved), null);
                }
            }
        }

        private void ParseData(byte[] data, int numReceived)
        {
            string packetHex;
            string packetAscii;

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

                    packetHex = BitConverter.ToString(byteData).Replace("-", String.Empty).Substring(0, numReceived * 2);
                    packetAscii = Encoding.ASCII.GetString(byteData).Substring(0, numReceived);

                    //creating new PacketInfo object to fill the buffer
                    PacketInfo pkgInfo = new PacketInfo(ipPacket, tcpPacket, packetHex, packetAscii);

                    //creating new list item to fill the list view control
                    PacketData packet = new PacketData
                    {
                        Number = numPacketsReceived.ToString(),
                        Time_Stamp = DateTime.Now.ToString("HH:mm:ss:") + DateTime.Now.Millisecond.ToString(),
                        Source = ipPacket.SourceAddress.ToString(),
                        Destination = ipPacket.DestinationAddress.ToString(),
                        Protocol = ipPacket.Protocol,
                        Length = ipPacket.TotalLength
                    };

                    if (pkgBuffer.Count < maxBufferSize)
                    {
                        pkgBuffer.Add(strKey, pkgInfo);

                        Dispatcher.Invoke((() =>
                        {
                            dataGrid.Items.Add(packet);
                            bufferProgress.Value = (double) numPacketsReceived;
                            percentLabel.Content = (Math.Round(((double)numPacketsReceived / (double) maxBufferSize), 2) * 100).ToString() + "%";
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

        private void Set_Icon()
        {
            Uri iconUri = new Uri(@"C:\Users\SamJustice\Documents\Visual Studio 2015\Projects\Packet Sniffer\nose.png", UriKind.RelativeOrAbsolute);
            window.Icon = BitmapFrame.Create(iconUri);
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
                    IPnode.Foreground = Brushes.Green;

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
                    TCPnode.Foreground = Brushes.Blue;

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

                Show_Bytes(pkgInfo);
            }
        }

        public void Show_Bytes(PacketInfo pkgInfo)
        {
            if (showAscii == true)
            {
                textBlock.Inlines.Clear();

                textBlock.Inlines.Add(new Run("IP:") { FontSize = 16, Foreground = Brushes.Green, TextDecorations = TextDecorations.Underline });
                textBlock.Inlines.Add(new Run("\n\n"));

                textBlock.Inlines.Add(new Run(pkgInfo.packetAscii.Substring(0, pkgInfo.IP._bHeaderLength)));

                textBlock.Inlines.Add(new Run("\n\n"));
                textBlock.Inlines.Add(new Run("TCP:") { FontSize = 16, Foreground = Brushes.Blue, TextDecorations = TextDecorations.Underline });
                textBlock.Inlines.Add(new Run("\n\n"));

                textBlock.Inlines.Add(new Run(pkgInfo.packetAscii.Substring(pkgInfo.IP._bHeaderLength, pkgInfo.IP._usTotalLength - pkgInfo.IP._bHeaderLength)));
            }
            else
            {
                textBlock.Inlines.Clear();

                textBlock.Inlines.Add(new Run("IP:") { FontSize = 16, Foreground = Brushes.Green, TextDecorations = TextDecorations.Underline });
                textBlock.Inlines.Add(new Run("\n\n"));

                textBlock.Inlines.Add(new Run(pkgInfo.packetHex.Substring(0, pkgInfo.IP._bHeaderLength * 2)));

                textBlock.Inlines.Add(new Run("\n\n"));
                textBlock.Inlines.Add(new Run("TCP:") { FontSize = 16, Foreground = Brushes.Blue, TextDecorations = TextDecorations.Underline });
                textBlock.Inlines.Add(new Run("\n\n"));

                textBlock.Inlines.Add(new Run(pkgInfo.packetHex.Substring(pkgInfo.IP._bHeaderLength * 2, (pkgInfo.IP._usTotalLength - pkgInfo.IP._bHeaderLength) * 2)));
            }

            /*textBlock.Inlines.Add(new Run(pkgInfo.IP._bVersionAndHeader.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.IP._bTypeOfService.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.IP._usTotalLength.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.IP._usIdentification.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.IP._usFlagsAndOffset.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.IP._bTTL.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.IP._bProtocol.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.IP._sChecksum.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.IP._uiSourceAddress.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.IP._uiDestinationAddress.ToString("X")));

            textBlock.Inlines.Add(new Run("\n\n"));
            textBlock.Inlines.Add(new Run("TCP:") { FontSize = 16, Foreground = Brushes.Blue, TextDecorations = TextDecorations.Underline });
            textBlock.Inlines.Add(new Run("\n\n"));

            textBlock.Inlines.Add(new Run(pkgInfo.TCP._usSourcePort.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.TCP._usDestinationPort.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.TCP._uiSequenceNumber.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.TCP._uiAckNumber.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.TCP._bHeaderLength.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.TCP._usDataOffsetAndFlags.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.TCP._usWindow.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.TCP._sChecksum.ToString("X")));
            textBlock.Inlines.Add(new Run(pkgInfo.TCP._usUrgentPointer.ToString("X")));

            byte[] tcpData = pkgInfo.TCP.Data;

            for (int x = 0; x < pkgInfo.TCP._usMessageLength; x++)
            {
                textBlock.Inlines.Add(new Run(tcpData[x].ToString("X")));
            }*/
        }

        private void asciiButton_Checked(object sender, RoutedEventArgs e)
        {
            if (showAscii != true)
            {
                if (dataGrid.SelectedItems.Count > 0)
                {
                    showAscii = true;

                    PacketData currentPacket = (PacketData)dataGrid.SelectedItem;

                    //getting the number of selected packet which is used as  an key in dictionary
                    string index = currentPacket.Number;

                    PacketInfo pkgInfo = new PacketInfo();

                    //trying to get data with specified key if this data exists 
                    if (pkgBuffer.TryGetValue(index, out pkgInfo))
                    {
                        textBlock.Inlines.Clear();

                        textBlock.Inlines.Add(new Run("IP:") { FontSize = 16, Foreground = Brushes.Green, TextDecorations = TextDecorations.Underline });
                        textBlock.Inlines.Add(new Run("\n\n"));

                        textBlock.Inlines.Add(new Run(pkgInfo.packetAscii.Substring(0, pkgInfo.IP._bHeaderLength)));

                        textBlock.Inlines.Add(new Run("\n\n"));
                        textBlock.Inlines.Add(new Run("TCP:") { FontSize = 16, Foreground = Brushes.Blue, TextDecorations = TextDecorations.Underline });
                        textBlock.Inlines.Add(new Run("\n\n"));

                        textBlock.Inlines.Add(new Run(pkgInfo.packetAscii.Substring(pkgInfo.IP._bHeaderLength, pkgInfo.IP._usTotalLength - pkgInfo.IP._bHeaderLength)));
                    }
                }
            }
        }

        private void hexButton_Checked(object sender, RoutedEventArgs e)
        {
            if (showAscii != false)
            {
                if (dataGrid.SelectedItems.Count > 0)
                {
                    showAscii = false;

                    PacketData currentPacket = (PacketData)dataGrid.SelectedItem;

                    //getting the number of selected packet which is used as  an key in dictionary
                    string index = currentPacket.Number;

                    PacketInfo pkgInfo = new PacketInfo();

                    //trying to get data with specified key if this data exists 
                    if (pkgBuffer.TryGetValue(index, out pkgInfo))
                    {
                        textBlock.Inlines.Clear();

                        textBlock.Inlines.Add(new Run("IP:") { FontSize = 16, Foreground = Brushes.Green, TextDecorations = TextDecorations.Underline });
                        textBlock.Inlines.Add(new Run("\n\n"));

                        textBlock.Inlines.Add(new Run(pkgInfo.packetHex.Substring(0, pkgInfo.IP._bHeaderLength * 2)));

                        textBlock.Inlines.Add(new Run("\n\n"));
                        textBlock.Inlines.Add(new Run("TCP:") { FontSize = 16, Foreground = Brushes.Blue, TextDecorations = TextDecorations.Underline });
                        textBlock.Inlines.Add(new Run("\n\n"));

                        textBlock.Inlines.Add(new Run(pkgInfo.packetHex.Substring(pkgInfo.IP._bHeaderLength * 2, (pkgInfo.IP._usTotalLength - pkgInfo.IP._bHeaderLength) * 2)));
                    }
                }
            }
        }

        private void maxBufferText_TextLoaded(object sender, TextChangedEventArgs e)
        {
            if (bufferProgress == null && Double.Parse(maxBufferText.Text) > 10)
            {
                maxBufferSize = Int32.Parse(maxBufferText.Text);
            }
        }

        private void maxBufferText_TextChanged(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Return)
            {
                if (bufferProgress != null && Double.Parse(maxBufferText.Text) > 10)
                {
                    bufferProgress.Maximum = Double.Parse(maxBufferText.Text);
                    maxBufferSize = Int32.Parse(maxBufferText.Text);
                }
                else if (bufferProgress != null && Double.Parse(maxBufferText.Text) < 10)
                {
                    MessageBox.Show("Buffer size cannot be less than 10. The buffer size was set to ten.", "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Error);
                    maxBufferText.Text = "10";
                    bufferProgress.Maximum = 10.0;
                    maxBufferSize = 10;
                }
            }
        }
    }
}
