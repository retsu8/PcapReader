package pcapreader;

import java.io.*;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import org.jnetpcap.Pcap;  
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;  
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.*;
/*
 * @author William Paddock, CSCI 476
 */
/*
* Prints info on captured TCP SYN packets (one line/packet) in an infinute loop
*/
public class PcapReader {
    public final Pcap pcap = null;
    public static String IPADDRESS_PATTERN = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
    public class PolicyTemplete{    
        private String Name = "";
        private String Type = "";
        private String proto = "";
        private String host = "";
        private String host_port = "";
        private String attacker_port = "";
        private String attacker = "";
        private String to_host = "";
        private PolicyTemplete(String Name, String Type, String proto, String host, String host_port, String attacker_port, String attacker, String to_host){
            this.Name = Name;
            this.Type = Type;
            this.proto = proto;
            this.host = host;
            this.host_port = host_port;
            this.attacker_port = attacker_port;
            this.attacker = attacker;
            this.to_host = to_host;
        }
    }
    private static void checkpolicy(PolicyTemplete inEffect) {
        if("".equals(inEffect.Name)){
            System.out.println("Name missing in policy, please add one");
            System.exit(0);
        }if("".equals(inEffect.Type)){
            System.out.println("Type missing in policy, please add one");
            System.exit(0);
        }if("".equals(inEffect.host)){
            System.out.println("host missing in policy, please add one");
            System.exit(0);
        }if("".equals(inEffect.host_port)){
            System.out.println("host_port missing in policy, please add one");
            System.exit(0);
        }if("".equals(inEffect.attacker_port)){
            System.out.println("attacker_port missing in policy, please add one");
            System.exit(0);
        }if("".equals(inEffect.attacker)){
            System.out.println("attacker missing in policy, please add one");
            System.exit(0);
        }if("".equals(inEffect.to_host)){
            System.out.println("to_host missing in policy, please add one");
            System.exit(0);
        }
    }
    private static void readpolicy(String policyFile, PolicyTemplete inEffect){
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(policyFile));
            String line = "";
            System.out.println("Building policy");
            while ((line = br.readLine()) != null)
            {
                line = line.trim();
                if(line.contains("host")){
                    Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
                    Matcher matcher = pattern.matcher(line);
                    if (matcher.find()) {
                        inEffect.host = matcher+"";
                    }
                    else{
                        System.out.println("No host found please repair policy file");
                        System.exit(0);
                    }                 
                }else if(line.contains("name")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.Name = line;
                }else if(line.contains("type")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    if(line.contains("stateful") || line.contains("stateless")){
                        inEffect.Type = line;
                    }
                    else{
                        System.out.println("Not stateless or stateful, must be set!!");
                        System.exit(0);
                    }
                }else if(line.contains("proto")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.proto = line;
                }else if(line.contains("host_port")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    if(line.contains("any") || ((Integer.parseInt(line) < 62001) && (Integer.parseInt(line) > 0))){
                        inEffect.host_port = line;
                    }else{
                        System.out.print("Port is not in the range 1-62000 or any, Do not use ZERO");
                        }
                }else if(line.contains("attacker_port")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    if(line.contains("any") || ((Integer.parseInt(line) < 62001) && (Integer.parseInt(line) > 0))){
                        inEffect.attacker_port = line;
                    }else{
                        System.out.print("Port is not in the range 1-62000 or any, Do not use ZERO");
                        }
                }else if(line.contains("attacker")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.attacker = line;
                }else if(line.contains("to_host")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.to_host = line;
                }
            }   
        } catch (FileNotFoundException ex) {
            Logger.getLogger(PcapReader.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                br.close();
            } catch (IOException ex) {
                Logger.getLogger(PcapReader.class.getName()).log(Level.SEVERE, null, ex);
            }
        }       
    }
    public static void main(String[] args) {
        String pcapFile = args[0];
        String policyFile = args[1];
        pcapRead(pcapFile, policyFile);
    }  

    public static void pcapRead(String pcapFile, String policyFile) {  
        //Creating policy Class
        PolicyTemplete inEffect;
        //setting all policy to null
        inEffect = PolicyTemplete(null, null, null, null, null, null, null, null);
        //Building Policy
        readpolicy(policyFile, inEffect);
        checkpolicy(inEffect);
        checkpcap(inEffect, pcapFile);
    }
    public static Pcap checkpcap(PolicyTemplete inEffect, String pcapFile) {
        StringBuilder errbuf = new StringBuilder(); 
        //Opening capture file
        final Pcap pcap = Pcap.openOffline(pcapFile, errbuf);
        String line = "";
        System.out.println("Scanning");
        //Set for stateless or stateful
        Boolean state = inEffect.Type.equalsIgnoreCase("stateful");
        if (pcap == null) {  
            System.err.println(errbuf); // Error is stored in errbuf if any  
        }
        JScanner.getThreadLocal().setFrameNumber(0); 
        if (state){
            JFlowMap superFlowMap = new JFlowMap();
            pcap.loop(Pcap.LOOP_INFINITE, superFlowMap, null);
            }
        final PcapPacket packet = new PcapPacket(JMemory.POINTER);  
        final Tcp tcp = new Tcp();  
        pcap.loop(-1, new JPacketHandler<StringBuilder>(){
            final Tcp tcp = new Tcp();
            final Http http = new Http;
            public void nextPacket(JPacket packet, StringBuilder errbuf){
                if(packet.hasHeader(Tcp.ID))
                    packet.getHeader(tcp);
            }
        }
            
                for (int i = 0; i < Pcap.LOOP_INFINITE; i++) {  
            final Http http = new Http();
            pcap.nextEx(packet);  
                if (packet.hasHeader(tcp)) {  
                    packet.filterByType(type);
                }  
        }
        return null;
    }
}