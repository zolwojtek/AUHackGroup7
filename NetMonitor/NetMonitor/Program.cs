using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Timers;
using System.Net;
using System.Threading;

namespace NetMonitor
{
    public enum Protocol
    {
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };

    class Program
    {
        static Socket mainSocket;                          //The socket which captures all incoming packets
        static byte[] byteData = new byte[4096];
        static  bool bContinueCapturing = false;            //A flag to check if packets are to be captured or not
        static List<string> IPs = new List<string>();

        static void Main(string[] args)
        {
            SnifferForm_Load();
            
                //if (!bContinueCapturing)
                //{
                //Start capturing the packets...

                //btnStart.Text = "&Stop";

                bContinueCapturing = true;

                //For sniffing the socket to capture the packets has to be a raw socket, with the
                //address family being of type internetwork, and protocol being IP
                mainSocket = new Socket(AddressFamily.InterNetwork,
                    SocketType.Raw, ProtocolType.IP);

                //Bind the socket to the selected IP address
                mainSocket.Bind(new IPEndPoint(IPAddress.Parse(IPs.Last()), 0));

                //Set the socket  options
                mainSocket.SetSocketOption(SocketOptionLevel.IP,            //Applies only to IP packets
                                           SocketOptionName.HeaderIncluded, //Set the include the header
                                           true);                           //option to true

                byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                byte[] byOut = new byte[4] { 1, 0, 0, 0 }; //Capture outgoing packets

                //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                mainSocket.IOControl(IOControlCode.ReceiveAll,              //Equivalent to SIO_RCVALL constant
                                                                            //of Winsock 2
                                     byTrue,
                                     byOut);

                //Start receiving the packets asynchronously
                mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                    new AsyncCallback(OnReceive), null);
            while (true)
            {

            } 
            //else
            //{
            //    //btnStart.Text = "&Start";
            //    bContinueCapturing = false;
            //    //To stop capturing the packets close the socket
            //    mainSocket.Close();
            //}
        }
            //}
            //}

        

        private static void OnReceive(IAsyncResult ar)
        {
            try
            {
                int nReceived = mainSocket.EndReceive(ar);

                //Analyze the bytes received...

                ParseData(byteData, nReceived);

                if (bContinueCapturing)
                {
                    byteData = new byte[4096];

                    //Another call to BeginReceive so that we continue to receive the incoming
                    //packets
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                        new AsyncCallback(OnReceive), null);
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                //MessageBox.Show(ex.Message, "MJsniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static DateTime startTime = new DateTime(1000, 1, 1);//fake impossible date
        static System.Timers.Timer timer = new System.Timers.Timer();

        private static void timerInit()
        {
            timer.Dispose();
            timer = new System.Timers.Timer();
            timer.AutoReset = false;
            timer.Interval = 120000;
            timer.Enabled = true;
            timer.Elapsed += new System.Timers.ElapsedEventHandler(onTimedEvent);
        }

        private static void trackTime()
        {
            if (startTime == new DateTime(1000, 1, 1))
            {
                startTime = DateTime.Now;
                timerInit();
                timer.Start();
            }
            else
            {
                timerInit();
                timer.Start();
            }


        }

        private static void onTimedEvent(object sender, ElapsedEventArgs e)
        {
            //now - startTime = time spent on fb to be written down
            Debug.WriteLine((DateTime.Now - startTime).TotalMinutes);
            timer.Stop();
            startTime = new DateTime(1000, 1, 1);
            //anders.stormer@gmail.com

        }

        static List<string> FacebookIps = new List<string>() { "66.220", "69.63.", "204.15", "31.13." };

        private static bool doesIpBelongsTo(string ip, List<string> webPortal)
        {
            if (webPortal.Contains(ip.Substring(0, 6)))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private static void ParseData(byte[] byteData, int nReceived)
        {

            //Since all protocol packets are encapsulated in the IP datagram
            //so we start by parsing the IP header and see what protocol data
            //is being carried by it
            IPHeader ipHeader = new IPHeader(byteData, nReceived);

            if (doesIpBelongsTo(ipHeader.DestinationAddress.ToString(), FacebookIps))
            {
                trackTime();
            }
            //Now according to the protocol being carried by the IP datagram we parse 
            //the data field of the datagram
           
        }
        
        private static void SnifferForm_Load()
        {
            string strIP = null;

            IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));
            if (HosyEntry.AddressList.Length > 0)
            {
                foreach (IPAddress ip in HosyEntry.AddressList)
                {
                    strIP = ip.ToString();
                    IPs.Add(strIP);
                }
            }
        }
    }
}
