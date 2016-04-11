/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pcapreader;

/**
 *
 * @author retsu
 */
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
