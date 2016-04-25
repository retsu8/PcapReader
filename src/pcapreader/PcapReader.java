package pcapreader;

import java.io.*;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapBpfProgram;
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

    public static JFlowMap superFlowMap;
    public static Boolean found;

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
            br = new BufferedReader(new FileReader(policyFile));  
            String line = null;             
            Boolean didThis = false;
            while ((line = br.readLine()) != null){
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
        File pcapDir = new File("./pcapFiles");
        File policyDir = new File("./Policy");
        File[] pcapListing = pcapDir.listFiles();
        File[] policyListing = policyDir.listFiles();
        int[][] array = null;
        int i =0;
        int j = 0;
        if(policyListing != null){
            for(File policy : policyListing){
                policyFile = policy.toString();
                System.out.println("Policy " + policy);
                if (pcapListing != null) {
                    for (File pcap : pcapListing){
                    System.out.println("PCap " + pcap);
                    pcapFile = pcap.toString(); //pcap here for new pcap file
                    pcapRead(pcapFile, policyFile);
                    if(found){
                        System.out.println("1");
                    }
                    i++;
                    }                
                }j++;
            }
        }
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
        found = false;
        Boolean state= false;
        StringBuilder errbuf = new StringBuilder(); 
        //Opening capture file
        final Pcap pcap = Pcap.openOffline(pcapFile, errbuf);
        String line = "";
        //Set for stateless or stateful
        if("stateful".contains(Type)){
            state = true;}
        if (pcap == null) {  
            System.err.println(errbuf); // Error is stored in errbuf if any  
        }
        JScanner.getThreadLocal().setFrameNumber(0); 
        if (state){
            superFlowMap = new JFlowMap();
            pcap.loop(Pcap.LOOP_INFINITE, superFlowMap, null);
            }
        pcap.loop(-1, new JPacketHandler<StringBuilder>(){
            PcapPacket packet = new PcapPacket(JMemory.POINTER);  
            @Override
            public void nextPacket(JPacket packet, StringBuilder errbuf){
                Tcp tcp = new Tcp();
                Ip4 ip = new Ip4();
                Http http = new Http();
                Udp udp = new Udp();
                switch (proto)
                {
                    case "tcp":{
                        PcapBpfProgram program = new PcapBpfProgram();
                        String expression = "host " + host;
                        int optimize = 0;         // 0 = false
                        int netmask = 0xFFFFFF00; // 255.255.255.0
                        
                        if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) {
                            System.err.println(pcap.getErr());
                        }
                        
                        if (pcap.setFilter(program) != Pcap.OK) {
                            System.err.println(pcap.getErr());
                        }
                        found = true;
                    }
                    case "udp":{
                        if(packet.hasHeader(ip) && packet.hasHeader(udp)){
                            if((Integer.getInteger(host_port) == udp.source())|| "any".equalsIgnoreCase(host_port)){
                                if(host.equalsIgnoreCase(Arrays.toString(ip.destination()))|| "any".equalsIgnoreCase(host)){
                                    if(to_host.contains(packet.toString()) || "any".equalsIgnoreCase(to_host)){
                                        found = true;
                                    }                                        
                                }
                            }
                            else if(udp.source() == 69){
                                    if(to_host.contains(packet.toString()) || "any".equalsIgnoreCase(to_host)){
                                    found = true;
                                }
                            }
                        }
                    }
                    default:{
                        if(packet.hasHeader(ip) && packet.hasHeader(udp)){
                            if((Integer.getInteger(host_port) == udp.source())|| "any".equalsIgnoreCase(host_port)){
                                if(host.equalsIgnoreCase(ip.destination().toString())|| "any".equalsIgnoreCase(host)){
                                    if(to_host.contains(packet.toString()) || "any".equalsIgnoreCase(to_host)){
                                        found = true;
                                    }                                        
                                }
                            }
                        }
                    }
                }
            }
        }, errbuf);
        return null;
    }     
    private static byte[][] convertToBytes(String[] strings) {
        byte[][] data = new byte[strings.length][];
        for (int i = 0; i < strings.length; i++) {
            String string = strings[i];
            data[i] = string.getBytes(Charset.defaultCharset()); // you can chose charset
        }
        return data;
    }
    public static boolean isInteger(String s) {
            return isInteger(s,10);
        }

        public static boolean isInteger(String s, int radix) {
            if(s.isEmpty()) return false;
            for(int i = 0; i < s.length(); i++) {
                if(i == 0 && s.charAt(i) == '-') {
                    if(s.length() == 1) return false;
                    else continue;
                }
                if(Character.digit(s.charAt(i),radix) < 0) return false;
            }
            return true;
        }
    }