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

/*
 * The classes "PacketInfo", "PacketIP", and "PacketTCP" were obtained from a project posted on coderbag.com, which is the
 * personal website of Sergej Kuznecov. On his website, he states that he posted the classes so that "everyone can use 
 * them in any way they want". 
 * 
 * The webpage where I obtained Kuznecov's code is located at http://www.coderbag.com/Programming-C/Building-a-Network-Sniffer-in-NET.
 * 
 * The rest of the code was written by me.
 */

namespace Packet_Sniffer
{
    public partial class MainWindow : Window
    {
        private int numPacketsReceived = 0;
        private bool isCapturing;
        private bool isSocketConnected;
        private Socket internetSocket;
        private byte[] byteData = new byte[4096];
        private Thread captureThread;
        private Dictionary<string, PacketInfo> pkgBuffer = new Dictionary<string, PacketInfo>();
        private int maxBufferSize = 1000;
        private int lastBufferSize = 1000;
        private bool showAscii = true;

        //Load the application
        public MainWindow()
        {
            InitializeComponent();
            Load_Interfaces();
        }

        private void Start_Button_Click(object sender, RoutedEventArgs e)
        {

            //Verify an interface has been selected
            if (interfaceSelector.Text == "")
            {
                MessageBox.Show("Select an Interface to capture the packets.", "Packet Sniffer",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else if (!isCapturing)
            {
                if (pkgBuffer.Count < maxBufferSize)
                {
                    try
                    {
                        Start_Button.Content = "Stop";
                        Start_Button.Background = Brushes.Red;

                        //Create a socket with the address family "internetwork" and protocol "IP"
                        internetSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

                        //Bind the socket to the IP address the user selected
                        internetSocket.Bind(new IPEndPoint(IPAddress.Parse(interfaceSelector.SelectedItem.ToString()), 0));

                        //Configure the socket options
                        internetSocket.SetSocketOption(SocketOptionLevel.IP,           
                                                   SocketOptionName.HeaderIncluded,     
                                                   true);                               

                        byte[] byIn = new byte[4] { 1, 0, 0, 0 };
                        byte[] byOut = new byte[4] { 1, 0, 0, 0 };

                        internetSocket.IOControl(IOControlCode.ReceiveAll, byIn, byOut);

                        //The socket is connected
                        isSocketConnected = true;

                        //The application will now begin capturing packets
                        isCapturing = true;

                        //Create the thread used to capture packets
                        captureThread = new Thread(Packet_Recieved);
                        captureThread.Name = "Capture Thread";
                        captureThread.IsBackground = true;
                        captureThread.Start();

                    }
                    catch (Exception ex)
                    {
                        Start_Button.Content = "Start";
                        Start_Button.Background = Brushes.LimeGreen;

                        MessageBox.Show(ex.Message, "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                else
                {
                    MessageBox.Show("The packet buffer has reached its maximum capacity. Clear the buffer or increase the maximum buffer size in order to continue.",
                            "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            else
            {
                Stop_Capturing();
            }
        }

        private void Packet_Recieved()
        {

            while (isCapturing)
            {
                try
                {
                    //Receive up to 4096 bytes
                    int bytesReceived = internetSocket.Receive(byteData, 0, byteData.Length, SocketFlags.None);

                    //Analyze the bytes that have been received
                    if (bytesReceived > 0)
                    {
                        ParseData(byteData, bytesReceived);
                    }

                    Array.Clear(byteData, 0, byteData.Length);
                }
                catch (ObjectDisposedException ex)
                {
                    Console.WriteLine(ex.Message + "\r\n");
                }
                catch (Exception ex)
                {
                    Console.Write(ex.Message + "\r\n");
                }
            }
        }

        private void ParseData(byte[] data, int numReceived)
        {
            string packetHex;
            string packetAscii;

            if (data.Length > 0 && numReceived != 0)
            {
                //Parse the IP packet
                PacketIP ipPacket = new PacketIP(data, numReceived);

                if (ipPacket.Protocol == "TCP")
                {
                    //Make the key of the packet equal to the number of packets that have been received thus far
                    string strKey = (numPacketsReceived + 1).ToString();

                    //Parse the TCP packet
                    PacketTcp tcpPacket = new PacketTcp(ipPacket.Data, ipPacket.MessageLength);

                    //Convert the packet's bytes to Hex and ASCII
                    packetHex = BitConverter.ToString(byteData).Replace("-", String.Empty).Substring(0, numReceived * 2);
                    packetAscii = Encoding.ASCII.GetString(byteData).Substring(0, numReceived);

                    //Create a PacketInfo object to store in the dictionary
                    PacketInfo pkgInfo = new PacketInfo(ipPacket, tcpPacket, packetHex, packetAscii);

                    //Create a PacketData object to populate the datagrid
                    PacketData packet = new PacketData
                    {
                        Number = (numPacketsReceived + 1).ToString(),
                        Time_Stamp = DateTime.Now.ToString("HH:mm:ss:") + DateTime.Now.Millisecond.ToString(),
                        Source = ipPacket.SourceAddress.ToString() + ":" + tcpPacket.SourcePort,
                        Destination = ipPacket.DestinationAddress.ToString() + ":" + tcpPacket.DestinationPort,
                        Protocol = ipPacket.Protocol,
                        Length = ipPacket.TotalLength,
                        Info = tcpPacket.Flags
                    };

                    //If the buffer is not full, add the packet to the buffer and display it in the datagrid
                    if (pkgBuffer.Count < maxBufferSize)
                    {
                        pkgBuffer.Add(strKey, pkgInfo);
                        numPacketsReceived++;

                        Dispatcher.Invoke((() =>
                        {
                            dataGrid.Items.Add(packet);
                            bufferProgress.Value = (double) numPacketsReceived;
                            percentLabel.Content = (Math.Round(((double) numPacketsReceived / (double) maxBufferSize), 2) * 100).ToString() + "%";
                        }), DispatcherPriority.ContextIdle);
                    }
                    else
                    {
                        //Stop capturing packets because the buffer is full
                        MessageBox.Show("The packet buffer has reached its maximum capacity. Clear the buffer or increase the maximum buffer size in order to continue.", 
                            "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Warning);

                        Dispatcher.Invoke((() =>
                        {
                            Stop_Capturing();
                        }), DispatcherPriority.ContextIdle);
                    }
                }
            }
        }

        private void Load_Interfaces()
        {
            //List the available interfaces in the drop down menu
            string hostName = Dns.GetHostName();
            IPAddress[] IPs = Dns.GetHostAddresses(hostName);

            foreach (IPAddress ip in IPs)
            {
                interfaceSelector.Items.Add(ip.ToString());
            }
        }

        //Clear the buffer and the data listed in the datagrid
        private void bufferClearButton_Click(object sender, RoutedEventArgs e)
        {
            dataGrid.Items.Clear();
            treeView.Items.Clear();
            textBlock.Inlines.Clear();
            pkgBuffer.Clear();
            bufferProgress.Value = 0;
            numPacketsReceived = 0;
            percentLabel.Content = "0%";
        }

        //Stop capturing packets
        private void Stop_Capturing()
        {
            isCapturing = false;

            Start_Button.Content = "Start";
            Start_Button.Background = Brushes.LimeGreen;

            if (captureThread.IsAlive)
                captureThread.Abort();

            //To stop capturing the packets close the socket
            if (isSocketConnected == true)
            {
                internetSocket.Shutdown(SocketShutdown.Both);
                internetSocket.Close();
                isSocketConnected = false;
            }
        }

        private void createPacketTree(object sender, SelectionChangedEventArgs e)
        {
            if (dataGrid.SelectedItems.Count > 0)
            { 
                PacketData currentPacket = (PacketData)dataGrid.SelectedItem;

                //Get the key of the packet that is currently selected in the datagrid
                string index = currentPacket.Number;

                PacketInfo pkgInfo = new PacketInfo();

                //Get the packet from the buffer whose key is the index obtained above
                if (pkgBuffer.TryGetValue(index, out pkgInfo))
                {
                    //If the packet is a TCP packet, add it to the detailed tree view
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

                    //Show the raw packet data in the text box to the right of the detailed tree view
                    Show_Bytes(pkgInfo);
                }
            }
        }

        public void Show_Bytes(PacketInfo pkgInfo)
        {
            //Display the raw packet data as ASCII characters
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
            //Display the raw packet data as Hex
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
        }

        //Display the raw packet data as ASCII characters
        private void asciiButton_Checked(object sender, RoutedEventArgs e)
        {
            if (showAscii != true)
            {
                showAscii = true;

                if (dataGrid.SelectedItems.Count > 0)
                {

                    PacketData currentPacket = (PacketData)dataGrid.SelectedItem;

                    //Get the key of the packet that is currently selected in the datagrid
                    string index = currentPacket.Number;

                    PacketInfo pkgInfo = new PacketInfo();

                    //Get the packet from the buffer whose key is the index obtained above
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

        //Display the raw packet data as Hex
        private void hexButton_Checked(object sender, RoutedEventArgs e)
        {
            if (showAscii != false)
            {
                showAscii = false;

                if (dataGrid.SelectedItems.Count > 0)
                {

                    PacketData currentPacket = (PacketData)dataGrid.SelectedItem;

                    //Get the key of the packet that is currently selected in the datagrid
                    string index = currentPacket.Number;

                    PacketInfo pkgInfo = new PacketInfo();

                    //Get the packet from the buffer whose key is the index obtained above
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

        //Alter the progress bar and progress label as the user changes the maximum buffer size
        private void maxBufferText_TextChanged(object sender, KeyEventArgs e)
        {
            int userInput = 0;
            
            //Only change the maximum buffer size when the user presses the enter key
            if (e.Key == Key.Return)
            {
                //Verify the user's input is valid
                try
                {
                    userInput = Int32.Parse(maxBufferText.Text);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Invalid Input!", "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Error);

                    maxBufferText.Text = lastBufferSize.ToString();

                    return;
                }

                //Make sure the minimum buffer size is 10 packets
                if (bufferProgress != null && userInput >= 10)
                {
                    //Display an error if the user tries to set the maximum buffer size to a number smaller than the number of
                    //packets that are already in the buffer
                    if (pkgBuffer.Count < userInput)
                    {
                        bufferProgress.Maximum = (double)userInput;
                        maxBufferSize = userInput;
                        percentLabel.Content = (Math.Round(((double)numPacketsReceived / (double)maxBufferSize), 2) * 100).ToString() + "%";
                        lastBufferSize = userInput;
                    }
                    else
                    {
                        MessageBox.Show("Packet buffer size cannot be set to a number smaller than the number of packets already received.",
                            "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Error);

                        maxBufferText.Text = lastBufferSize.ToString();
                    }
                }
                else if (bufferProgress != null && userInput < 10)
                {
                    MessageBox.Show("Buffer size cannot be less than 10.", "Packet Sniffer", MessageBoxButton.OK, MessageBoxImage.Error);

                    maxBufferText.Text = lastBufferSize.ToString();
                }
            }
        }
    }
}
