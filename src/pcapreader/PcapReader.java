
package pcapreader;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
/**
 *
 * @author William Paddock, CSCI 476
 */
/*
* Prints info on captured TCP SYN packets (one line/packet) in an infinute loop
*/
public class PcapReader {

    public void start() {
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
        int snaplen = 64 * 1024;                    // Capture whole packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS;      
        int timeout = 10 * 1000;                    // 10 seconds in millis  

        Pcap pcap =
                Pcap.openLive("eth0", snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            throw new RuntimeException("failed to open eth0 for capture: " + errbuf.toString());
        }

        PcapBpfProgram program = new PcapBpfProgram();
        String synExpression = // SYN flag on, ACK flag off
                "(tcp[tcpflags] & tcp-syn) != 0 and (tcp[tcpflags] & tcp-ack) == 0";
        int optimize = 1;   // 0 = false, 1 = true
        int netmask = 0;

        if (pcap.compile(program, synExpression, optimize, netmask) != Pcap.OK
                || pcap.setFilter(program) != Pcap.OK) {
            throw new RuntimeException("filter init error: " + pcap.getErr());
        }


        JPacketHandler<String> packetHandler = new JPacketHandler<String>() {

            private Ip4 ip = new Ip4();
            private Tcp tcp = new Tcp();

            @Override
            public void nextPacket(JPacket packet, String user) {

                StringBuilder info = new StringBuilder();

                if (!packet.hasHeader(ip) || !packet.hasHeader(tcp)) {
                    throw new RuntimeException("tcp syn filter is bad");
                }

                info.append(tcpEndPointStr(ip.source(), tcp.source()));
                info.append(" > ");
                info.append(tcpEndPointStr(ip.destination(), tcp.destination()));

                info.append(" ip.length=");
                info.append(ip.getLength());
                info.append(" ip.ttl=");
                info.append(ip.ttl());

                info.append(" tcp.seq=");
                info.append(tcp.seq());
                info.append(" tcp.window=");
                info.append(tcp.window());

                info.append(" Flags[");
                int count = 0;
                for (Tcp.Flag cntrlFlag : tcp.flagsEnum()) {
                    if (count++ > 0) {
                        info.append(" ");
                    }
                    info.append(cntrlFlag);
                }
                info.append("]");


                info.append(" Options[");
                count = 0;
                for (JHeader subheader : tcp.getSubHeaders()) {

                    if (count++ > 0) {
                        info.append(" ");
                    }

                    if (subheader instanceof Tcp.NoOp) {
                        info.append("noOp");
                    } else if (subheader instanceof Tcp.SACK_PERMITTED) {
                        info.append("sackOK");
                    } else if (subheader instanceof Tcp.MSS) {
                        Tcp.MSS mss = (Tcp.MSS) subheader;
                        info.append("mss=");
                        info.append(mss.mss());
                    } else if (subheader instanceof Tcp.WindowScale) {
                        Tcp.WindowScale ws = (Tcp.WindowScale) subheader;
                        info.append("wscale=");
                        info.append(ws.scale());
                    } else if (subheader instanceof Tcp.Timestamp) {
                        Tcp.Timestamp ts = (Tcp.Timestamp) subheader;
                        info.append("ts=");
                        info.append(ts.tsval());
                    } else if (subheader instanceof Tcp.TcpOption) {
                        Tcp.TcpOption opt = (Tcp.TcpOption) subheader;
                        info.append("UNEXPECTED_KIND=");
                        info.append(opt.code());
                        info.append(")");
                    } else {
                        info.append("UNEXPECTED_JHEADER_CLASS=");
                        info.append(subheader.getClass());
                        info.append(")");
                    }
                }
                info.append("]");

                System.out.println(info);
            }
        };

        pcap.loop(Pcap.LOOP_INFINITE, packetHandler, "jNetPcap ru1ez!");
    }

    private static String tcpEndPointStr(byte addrBytes[], int port) {
        String addr;
        try {
            addr = InetAddress.getByAddress(addrBytes).getHostAddress();
        } catch (UnknownHostException ex) {
            addr = "-";
        }
        return addr + ":" + port;
    }
    
    public static void main(String[] args) {
        new PcapReader().start();
    }
}
