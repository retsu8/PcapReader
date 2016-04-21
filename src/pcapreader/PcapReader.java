package pcapreader;

import java.io.*;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.sound.sampled.Port;
import org.jnetpcap.Pcap;  
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;  
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.*;
/*
 * @author William Paddock, CSCI 476
 */
/*
* Prints info on captured TCP SYN packets (one line/packet) in an infinute loop
*/
public class PcapReader {
    public final Pcap pcap = null;
    public static String IPADDRESS_PATTERN =  "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
    private static String Name;
    private static String Type;
    private static String proto;
    private static String host;
    private static String host_port;
    private static String attacker_port;
    private static String attacker;
    private static String to_host;
    private static void checkpolicy(){
        if(Name.isEmpty()){
            System.out.println("Name missing in policy, please add one");
            System.exit(0);
        }if(Type.isEmpty()){
            System.out.println("Type missing in policy, please add one");
            System.exit(0);
        }if(host.isEmpty()){
            System.out.println("host missing in policy, please add one");
            System.exit(0);
        }if(host_port.isEmpty()){
            System.out.println("host_port missing in policy, please add one");
            System.exit(0);
        }if(attacker_port.isEmpty()){
            System.out.println("attacker_port missing in policy, please add one");
            System.exit(0);
        }if(attacker.isEmpty()){
            System.out.println("attacker missing in policy, please add one");
            System.exit(0);
        }if(to_host.isEmpty()){
            System.out.println("to_host missing in policy, please add one");
            System.exit(0);
        }
    }
    private static void readpolicy(String policyFile) throws IOException{
        BufferedReader br = null;
        try {
            System.out.println("Building policy");
            br = new BufferedReader(new FileReader(policyFile));  
            String line = null;             
            Boolean didThis = false;
            while ((line = br.readLine()) != null){
                System.out.println("" + line);
                line = line.trim();
                if(line.contains("host") && didThis == false){
                    line = line.trim();
                    Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
                    Matcher matcher = pattern.matcher(line);
                    if (matcher.find()){
                        host = matcher.matches() + "";
                        didThis = true;
                    }
                    else{
                        System.out.println("No host found please repair policy file");
                        System.exit(0);
                    }                 
                }else if(line.contains("name")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    line = line.trim();
                    Name = line;
                }else if(line.contains("type")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    line = line.trim();
                    if(line.contains("stateful") || line.contains("stateless")){
                        System.out.println("" + line);
                        Type = line;
                    }
                    else{
                        System.out.println("Not stateless or stateful, must be set!!");
                        System.exit(0);
                    }
                }else if(line.contains("proto")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    line = line.trim();
                    proto = line;
                }else if(line.contains("host_port")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    line = line.trim();
                    if(line.contains("any") || ((Integer.parseInt(line) < 62001) && (Integer.parseInt(line) > 0))){
                        host_port = line;
                    }else{
                        System.out.print("Port is not in the range 1-62000 or any, Do not use ZERO");
                        }
                }else if(line.contains("attacker_port")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    line = line.trim();
                    if(line.contains("any") || ((Integer.parseInt(line) < 62001) && (Integer.parseInt(line) > 0))){
                        attacker_port = line;
                    }else{
                        System.out.print("Port is not in the range 1-62000 or any, Do not use ZERO");
                        }
                }else if(line.contains("attacker")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    line = line.trim();
                    attacker = line;
                }else if(line.contains("to_host")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    line = line.trim();
                    to_host = line;
                }
            }   
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PcapReader.class.getName()).log(Level.SEVERE, null, ex);
        }        
    }
    public static void main(String[] args) throws IOException {
        String pcapFile;
        String policyFile;
        System.out.println("Importing Pcap File");
        pcapFile = "trace1.pcap"; //change here for new pcap file
        //pcapFile = args[0]; //import pcap
        System.out.println("Imported");
        System.out.println("Importing Policy File");
        policyFile = "./policy1.txt"; //change here for new policy file
        //policyFile = args[1]; //import policy
        System.out.println("Imported");
        pcapRead(pcapFile, policyFile);
    }  

    public static void pcapRead(String pcapFile, String policyFile) throws IOException {  
        //Creating policy Class
        //setting all policy to null
        //Building Policy
        readpolicy(policyFile);
        //checkpolicy();
        checkpcap(pcapFile);
    }
    public static Pcap checkpcap(String pcapFile) {
        System.out.println("Policy Name " + Name);
        Boolean state= false;
        StringBuilder errbuf = new StringBuilder(); 
        //Opening capture file
        final Pcap pcap = Pcap.openOffline(pcapFile, errbuf);
        String line = "";
        System.out.println("Scanning");
        //Set for stateless or stateful
        if("stateful".contains(Type)){
            state = true;}
        System.out.println("Setting State");
        if (pcap == null) {  
            System.err.println(errbuf); // Error is stored in errbuf if any  
        }
        JScanner.getThreadLocal().setFrameNumber(0); 
        if (state){
            JFlowMap superFlowMap = new JFlowMap();
            pcap.loop(Pcap.LOOP_INFINITE, superFlowMap, null);
            }
        PcapPacket packet = new PcapPacket(JMemory.POINTER);  
        Tcp tcp = new Tcp();  
        pcap.loop(-1, new JPacketHandler<StringBuilder>(){
            Tcp tcp = new Tcp();
            Ip4 ip = new Ip4();
            Http http = new Http();
            Udp udp = new Udp();
            public void nextPacket(JPacket packet, StringBuilder errbuf){
                switch (proto)
                {
                    case "tcp":{
                        int host_portInt = 0;
                        packet.getHeader(tcp);
                        if(packet.hasHeader(Tcp.ID) && packet.hasHeader(tcp)){
                            if(!"any".equalsIgnoreCase(host_port) && !host_port.isEmpty()){
                                host_portInt = Integer.parseInt(host_port);}
                            if((host_portInt == tcp.source()) || "any".equalsIgnoreCase(host_port)){
                                if(host.contains("") &&(host.equals(ip.destination().toString())) || "any".equalsIgnoreCase(host)){
                                    if(to_host.contains(packet.toString()) || "any".equalsIgnoreCase(to_host)){
                                        System.out.printf("tcp header::%s%n", tcp.toString());
                                    }                                        
                                }
                            }
                        }break;
                    }
                    case "udp":{
                        if(packet.hasHeader(ip) && packet.hasHeader(udp)){
                            if((Integer.getInteger(host_port) == udp.source())|| "any".equalsIgnoreCase(host_port)){
                                if(host.equalsIgnoreCase(Arrays.toString(ip.destination()))|| "any".equalsIgnoreCase(host)){
                                    if(to_host.contains(packet.toString()) || "any".equalsIgnoreCase(to_host)){
                                        System.out.printf("udp header::%s%n", udp.toString());
                                    }                                        
                                }
                            }
                        }break;
                    }
                    default:{
                        if(packet.hasHeader(ip) && packet.hasHeader(udp)){
                            if((Integer.getInteger(host_port) == udp.source())|| "any".equalsIgnoreCase(host_port)){
                                if(host.equalsIgnoreCase(ip.destination().toString())|| "any".equalsIgnoreCase(host)){
                                    if(to_host.contains(packet.toString()) || "any".equalsIgnoreCase(to_host)){
                                        System.out.printf("header::%s%n", packet.toString());
                                    }                                        
                                }
                            }
                        }break;
                    }
                }
            }
        }, errbuf);
        return null;}
    private static byte[][] convertToBytes(String[] strings) {
        byte[][] data = new byte[strings.length][];
        for (int i = 0; i < strings.length; i++) {
            String string = strings[i];
            data[i] = string.getBytes(Charset.defaultCharset()); // you can chose charset
        }
        return data;
    }
    }