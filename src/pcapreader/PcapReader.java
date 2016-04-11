
package pcapreader;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jnetpcap.*;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.tcpip.Http;
/**
 *
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
        if(inEffect.Name == ""){
            System.out.println("Name missing in policy, please add one");
            System.exit(0);
        }if(inEffect.Type == ""){
            System.out.println("Type missing in policy, please add one");
            System.exit(0);
        }if(inEffect.proto == ""){
            System.out.println("proto missing in policy, please add one");
            System.exit(0);
        }if(inEffect.host == ""){
            System.out.println("host missing in policy, please add one");
            System.exit(0);
        }if(inEffect.host_port == ""){
            System.out.println("host_port missing in policy, please add one");
            System.exit(0);
        }if(inEffect.attacker_port == ""){
            System.out.println("attacker_port missing in policy, please add one");
            System.exit(0);
        }if(inEffect.attacker == ""){
            System.out.println("attacker missing in policy, please add one");
            System.exit(0);
        }if(inEffect.to_host == ""){
            System.out.println("to_host missing in policy, please add one");
            System.exit(0);
        }
    }
    private static void readpolicy(String policyFile, PolicyTemplete inEffect){
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(policyFile));
            String line = null;
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
                    }                 
                }else if(line.contains("name")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.Name = line;
                }else if(line.contains("type")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.Type = line;
                }else if(line.contains("proto")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.proto = line;
                }else if(line.contains("host_port")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.host_port = line;
                }else if(line.contains("host_port")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.Name = line;
                }else if(line.contains("attacker_port")){
                    int i = line.indexOf("=");
                    line = line.substring(i+1, line.length());
                    inEffect.attacker_port = line;
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
        String file = args[0];
        String policyFile = args[1];
        pcapRead(file, policyFile);
    }  

    public static void pcapRead(String file, String policyFile) {   
        StringBuilder errbuf = new StringBuilder();  
  
        final Pcap pcap = Pcap.openOffline(file, errbuf);
        PolicyTemplete inEffect
        inEffect = PolicyTemplete();
        inEffect = readpolicy(policyFile, inEffect);
        checkpolicy(inEffect);
    }  
    public Pcap search(pack){
        if (pack.hasHeader(tcp) && pack.hasHeader(http)) {  
         pack.getHeader(eth);
         pack.getHeader(tcp);
         pack.getHeader(ip4);

         if(tcp.destination() == 80) {
               if(http.hasField(Http.Request.Accept) && http.fieldValue(Http.Request.Accept).contains("text/html")) {

                   String dstIp = FormatUtils.ip(ip4.destination());
                   String srcIp = FormatUtils.ip(ip4.source());
                   String dstMac = FormatUtils.mac(eth.destination());
                   String srcMac = FormatUtils.mac(eth.source());

                   String host = http.fieldValue(Http.Request.Host);
                   String url = host + http.fieldValue(Http.Request.RequestUrl);
                   String referer =  http.fieldValue(Http.Request.Referer);

                   RecorderService.recordHttpRequest(srcMac, srcIp, dstIp, host, url, referer);
                   System.out.println("Request: " + srcIp + " - " + url);
                   //superFlowMap.nextPacket(packet, superFlowMap);
                }
          }
    }

