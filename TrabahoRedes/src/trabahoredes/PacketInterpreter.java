package trabahoredes;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.HashMap;
import javax.swing.JTextArea;

public class PacketInterpreter {

    /* Essa função concatena  ao começo da String 'bin',
    tornando visível os 0's à esquerda*/
    private String concatZero(String bin, int n) {
        String saida = bin;
        if (bin.length() < n) {
            for (int i = 0; bin.length() < n - i; i++) {
                saida = "0" + saida;
            }
        }
        return saida;
    }

    /*Essa função transforma uma cadeia de bits em pontos, deixando
    visível apenas o bit na posição 'n'. */
    private String fragmentationDatagram(String bin, int n) {
        String saida = "";

        for (int i = 0; i < bin.length(); i++) {
            if (i % 4 == 0) {
                saida += " ";
            }
            saida += (i == n) ? bin.charAt(i) : ".";
        }

        return saida;
    }

    private String fragmentationDatagram(String bin, int startIndex, int endIndex) {
        String saida = "";

        for (int i = 0; i < bin.length(); i++) {
            if (i % 4 == 0) {
                saida += " ";
            }
            saida += (i >= startIndex && i <= endIndex) ? bin.charAt(i) : ".";
        }

        return saida;
    }
    //Essa função verifica se há um padding de 0's até o final do pacote
    private boolean verifyPadding(String[] bytes, int n) {
        for (int i = n; i < bytes.length; i++) {
            if (!bytes[i].equals("00")) {
                return false;
            }
        }
        return true;
    }

    //Essa função lê um arquivo .csv e aloca os elementos do arquivo em um HashMap
    private HashMap<Integer, String> readCSV() {
        String row;
        HashMap<Integer, String> buffer = new HashMap<Integer, String>();

        try {
            BufferedReader csvReader = new BufferedReader(new FileReader(System.getProperty("user.dir") + "//ip_protocols.csv"));
            while ((row = csvReader.readLine()) != null) {
                String[] data = row.split(",");
                try {
                    buffer.put(Integer.parseInt(data[1]), data[2]);
                } catch (NumberFormatException nfe) {
                    if (data[1].matches("\\d+-\\d+")) {
                        String[] subdata = data[1].split("-");
                        for (int i = Integer.parseInt(subdata[0]); i < Integer.parseInt(subdata[1]); i++) {
                            buffer.put(i, data[2]);
                        }
                    }
                }
            }
        } catch (IOException ex) {
            return null;
        }
        return buffer;
    }

    //Essa função converte uma String hexadecimal em uma String UTF-16
    private String decryptHex(String bin) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < bin.length(); i += 2) {
            int range = 2;
            try {
                if (i + 2 > bin.length()) {
                    range = 1;
                }
                String str = bin.substring(i, i + range);
                output.append((char) Integer.parseInt(str, 16));
            } catch (NumberFormatException nfe) {
                continue;
            }
        }
        return output.toString();
    }

    //Essa função verifica se um endereço é broadcast ff:ff:ff:ff:ff:ff
    private boolean verifyBroadcast(String bin) {
        String[] bytes = bin.split(":");

        for (int i = 0; i < bytes.length; i++) {
            if (!bytes[i].equals("ff")) {
                return false;
            }
        }
        return true;
    }

    //Essa função calcula o número anterior mais próximo de n que seja divisvel por 16.
    private int calculateRange(int n) {
        int saida = 0;

        if (n > 64) 
            return 64;
        
        while (saida < n - 16) {
            saida += 16;
        }
        return saida;
    }

    public PacketInterpreter(String filename, JTextArea t) {
        TcpDumpHeader tdh;
        FrameHeader fh;
        RandomAccessFile in;
        int i;
        int qtdquadros;
        boolean wasLI;
        try {
            tdh = new TcpDumpHeader();
            fh = new FrameHeader();
            in = new RandomAccessFile(filename, "r");

            tdh.readHeader(in);
            if (tdh.isLittleEndian()) {
                wasLI = true;
            } else {
                wasLI = false;
            }

            if (wasLI) {
                tdh.toBigEndian();
            }

            if (t != null) {
                System.out.println("MAGIC NUMBER: " + Integer.toHexString(tdh.magic_number));
                System.out.println("\nVERSION: " + tdh.major_version + "." + tdh.minor_version);
                System.out.println("\nTIMEZONE: " + tdh.time_zone_off);
                System.out.println("\nTIMESTAMP: " + tdh.time_stamp);
                System.out.println("\nSNAP LENGTH: " + tdh.snap_length);
                System.out.println("\nLINK LAYER TYPE: " + tdh.link_layer_type);
                System.out.println("\n------------------------------\n\n");
            } else {
                System.out.println("MAGIC NUMBER: " + Integer.toHexString(tdh.magic_number));
                System.out.println("\nVERSION: " + tdh.major_version + "." + tdh.minor_version);
                System.out.println("\nTIMEZONE: " + tdh.time_zone_off);
                System.out.println("\nTIMESTAMP: " + tdh.time_stamp);
                System.out.println("\nCAPTURE SIZE: " + tdh.snap_length);
                System.out.println("\nLINK LAYER SIZE: " + tdh.link_layer_type);
                System.out.println("\n------------------------------\n");
            }

            qtdquadros = 0;

            /*Contadores que armazenam a quantidade de 
                vezes que foi detectado um protocolo */
            int cEthernetFrame = 0;
            int cEthernetBroadcast = 0;
            int cARP = 0;
            int cIP = 0;
            int cICMP = 0;
            int cUDP = 0;
            int cTCP = 0;

            while (fh.readHeader(in)) {
                if (wasLI) {
                    if (t != null) {
                        System.out.println("\nPACKET " + qtdquadros + "\n");
                    } else {
                        System.out.println("PACKET " + qtdquadros);
                    }
                    fh.toBigEndian();
                }

                if (t != null) {
                    System.out.println("CAPTURE TIME: " + fh.seconds + "." + fh.mic_secs + "\n");
                    System.out.println("BYTE QUANTITY CAPTURED: " + fh.capt_data + "\n");
                    System.out.println("REAL PACKET SIZE: " + fh.actual_length + "\n");
                } else {
                    System.out.println(fh.seconds);
                    System.out.println(fh.mic_secs);
                    System.out.println(fh.capt_data);
                    System.out.println(fh.actual_length);
                }

                int[] buffer = new int[fh.capt_data];
                String[] bytes = new String[fh.capt_data];

                for (i = 0; i < fh.capt_data; i++) {
                    buffer[i] = in.readByte();
                }

                for (i = 0; i < fh.capt_data; i++) {
                    String hexString = Integer.toHexString(buffer[i]);

                    //Trata se o byte for negativo
                    if ((buffer[i] + "").startsWith("-")) {
                        hexString = hexString.substring(hexString.length() - 2);
                    }

                    //Trata se o número só tiver um dígito
                    if (hexString.length() == 1) {
                        hexString = "0" + hexString;
                    }

                    bytes[i] = hexString;
                }

                int iterator = 0;
                boolean hasStarted = false;
                boolean hasFinishEthernet = false;
                boolean hasFinishPayload = false;
                String protocol = "";
                int packageID = 0;

                //Ethernet
                String eDestination = "";
                String eSource = "";
                String etherType = "";

                //IPV
                String iVersion = "";
                String iHeaderlen = "";
                String iType = "";
                String iTotallen = "";
                String iTTL = "";
                String iProtocol = "";
                String iChecksum = "";
                String iSource = "";
                String iDestination = "";

                //List
                HashMap<Integer, String> iProtocolList = readCSV();

                //ARP
                String aHardwareType = "";
                String aProtocolType = "";
                String aHardwareAddressLength = "";
                String aProtocolAddressLength = "";
                String aOpcode = "";
                String aSenderHardwareAddress = "";
                String aSenderProtocolAddress = "";
                String aTargetHardwareAddress = "";
                String aTargetProtocolAddress = "";

                //TCP
                String tSourcePort = "";
                String tDestinationPort = "";
                String tSequenceNumber = "";
                String tAcknowledgementNumber = "";
                String tDataOffset = "";
                String tFlag = "";
                String tWindow = "";
                String tChecksum = "";
                String tUrgentPointer = "";
                String tData = "";

                //UDP
                String uSourcePort = "";
                String uDestinationPort = "";
                String uLength = "";
                String uChecksum = "";
                String uData = "";

                //ICMP
                String icType = "";
                String icCode = "";
                String icChecksum = "";

                while (iterator < fh.capt_data) {
                    if (!hasStarted) {
                        //Ethernet
                        if (!hasFinishEthernet) {
                            packageID++;
                            hasStarted = true;
                            protocol = "ETHER";
                            cEthernetFrame++;

                            //Initialize
                            eDestination = "";
                            eSource = "";
                            etherType = "";

                            System.out.println("\nETHER: ----- Ether Header -----\n");
                            System.out.println("ETHER:\n");
                            System.out.println("ETHER: Packet " + packageID + "\n");
                            System.out.println("ETHER: Packet size = " + fh.capt_data + " bytes \n");

                        } else if (hasFinishEthernet && !hasFinishPayload) {
                            String iBinary;
                            //IP
                            if (etherType.equals("0800 (IP)")) {
                                packageID++;
                                hasStarted = true;
                                protocol = "IP";
                                cIP++;

                                //Initialize
                                iVersion = "";
                                iHeaderlen = "";
                                iType = "";
                                iTotallen = "";
                                iTTL = "";
                                iProtocol = "";
                                iChecksum = "";
                                iSource = "";
                                iDestination = "";

                                iBinary = Integer.toBinaryString(Integer.parseInt(bytes[iterator], 16));
                                iBinary = concatZero(iBinary, 8);

                                iVersion = Integer.parseInt(iBinary.substring(0, 4), 2) + "";
                                iHeaderlen = 4 * Integer.parseInt(iBinary.substring(4), 2) + "";

                                System.out.println("IP: ----- IP Header -----:\n");
                                System.out.println("IP:\n");
                                System.out.println("IP: Version " + iVersion + "\n");
                                System.out.println("Header length = " + iHeaderlen + " bytes\n");
                                iterator++;

                                //ARP
                            } else if (etherType.equals("0806 (ARP)")) {
                                packageID++;
                                hasStarted = true;
                                protocol = "ARP";
                                cARP++;

                                //Initialize
                                aHardwareType = "";
                                aProtocolType = "";
                                aHardwareAddressLength = "";
                                aProtocolAddressLength = "";
                                aOpcode = "";
                                aSenderHardwareAddress = "";
                                aSenderProtocolAddress = "";
                                aTargetHardwareAddress = "";
                                aTargetProtocolAddress = "";

                                System.out.println("ARP: ----- ARP/RARP Frame -----\n");
                                System.out.println("ARP:\n");
                            }
                        } else if (hasFinishEthernet & hasFinishPayload) {
                            //TCP
                            if (iProtocol.equals("6 (TCP)")) {
                                packageID++;
                                hasStarted = true;
                                protocol = "TCP";
                                cTCP++;

                                //Inicialize
                                tSourcePort = "";
                                tDestinationPort = "";
                                tSequenceNumber = "";
                                tAcknowledgementNumber = "";
                                tDataOffset = "";
                                tFlag = "";
                                tWindow = "";
                                tChecksum = "";
                                tData = "";
                                tUrgentPointer = "";

                                System.out.println("\nTCP: ----- TCP Header -----\n");
                                System.out.println("TCP:\n");
                                //UDP
                            } else if (iProtocol.equals("17 (UDP)")) {
                                packageID++;
                                hasStarted = true;
                                protocol = "UDP";
                                cUDP++;

                                //Initialize
                                uSourcePort = "";
                                uDestinationPort = "";
                                uLength = "";
                                uChecksum = "";
                                uData = "";

                                System.out.println("\nUDP: ----- UDP Header -----\n");
                                System.out.println("UDP:\n");

                            } else if (iProtocol.equals("1 (ICMP)")) {
                                packageID++;
                                hasStarted = true;
                                protocol = "ICMP";
                                cICMP++;

                                //Inicialize
                                icCode = "";
                                icType = "";
                                icChecksum = "";

                                System.out.println("\nICMP: ----- ICMP Header -----\n");
                                System.out.println("ICMP:\n");
                            }
                        }
                    }
                    hasFinishEthernet = false;
                    if (hasStarted) {
                        if (protocol.equals("ETHER")) {
                            for (int oi = iterator; oi < iterator + 6; oi++) {
                                eDestination += (oi != iterator + 5) ? bytes[oi] + ":" : bytes[oi];
                            }
                            iterator += 6;
                            for (int oi = iterator; oi < iterator + 6; oi++) {
                                eSource += (oi != iterator + 5) ? bytes[oi] + ":" : bytes[oi];
                            }
                            iterator += 6;
                            for (int oi = iterator; oi < iterator + 2; oi++) {
                                etherType += bytes[oi];
                            }
                            iterator += 1;

                            if (verifyBroadcast(eDestination)) {
                                eDestination += " (broadcast)";
                                cEthernetBroadcast++;
                            }

                            System.out.println("ETHER: Destination = " + eDestination + "\n");
                            System.out.println("ETHER: Source = " + eSource + "\n");

                            if (etherType.equals("0800")) {
                                etherType = etherType + " (IP)";
                            } else if (etherType.equals("0806")) {
                                etherType = etherType + " (ARP)";
                            }

                            System.out.println("ETHER: Ethertype = " + etherType + "\n");
                            System.out.println("ETHER:\n\n");

                            hasStarted = false;
                            hasFinishEthernet = true;

                        } else if (protocol.equals("IP")) {
                            //Type
                            String iBinary;
                            
                            iType = bytes[iterator] + "";
                            System.out.println("IP: Type of service = 0x" + iType + "\n");
                            
                            //Routine
                            iBinary = Integer.parseInt(bytes[iterator], 16) + "";
                            iBinary = concatZero(Integer.toBinaryString(Integer.parseInt(iBinary)), 8);
                            iType = iBinary;
                            
                            for (int z = 0; z < 6; z++) {
                                String subFlag = "";
                                if (iType.charAt(z) == '0') {
                                    subFlag += "normal ";
                                }else {
                                    subFlag += "low ";
                                }
                                
                                if(z >= 0 && z < 3) {
                                    subFlag += "Routine";
                                    System.out.println("IP: " + fragmentationDatagram(iType, 0, 2) + " = " + subFlag + "\n");
                                    z = 2;
                                    continue;
                                }
                                if (z == 3) {
                                    subFlag += "delay";
                                } else if (z == 4) {
                                    subFlag += "throughput";
                                } else if (z == 5) {
                                    subFlag += "reliability";
                                }
                                System.out.println("TCP: " + fragmentationDatagram(iType, z) + " = " + subFlag + "\n");
                            }
                    

                            //Total Length
                            iBinary = "";

                            iterator++;
                            iBinary += bytes[iterator];
                            iterator++;
                            iBinary += bytes[iterator];

                            iTotallen = Integer.parseInt(iBinary, 16) + "";
                            System.out.println("IP: Total length = " + iTotallen + " bytes\n");

                            //Identification
                            iBinary = "";

                            iterator++;
                            iBinary += bytes[iterator];
                            iterator++;
                            iBinary += bytes[iterator];

                            iTotallen = Integer.parseInt(iBinary, 16) + "";
                            System.out.println("IP: Identification " + iTotallen + "\n");

                            //Flags
                            iBinary = "";

                            iterator++;
                            iBinary += bytes[iterator];
                            iterator++;
                            iBinary += bytes[iterator];

                            System.out.println("IP: Flags = 0x" + iBinary + "\n");

                            iBinary = Integer.toBinaryString(Integer.parseInt(iBinary, 16));
                           
                            iBinary = concatZero(iBinary, 8);
                            System.out.println("IP: " + fragmentationDatagram(iBinary, 1) + " = may fragment\n");
                            System.out.println("IP: " + fragmentationDatagram(iBinary, 2) + " = more fragment\n");
                            
                            int iFragmentOffset = 0;
                            for(int z = 3; z < iBinary.length(); z++) {
                                if(iBinary.charAt(z) == '1') {
                                    iFragmentOffset++;
                                }
                            }
                            System.out.println("IP: Fragment offset = " + iFragmentOffset+ " bytes \n");

                            //TTL
                            iBinary = "";

                            iterator++;
                            iBinary += bytes[iterator];

                            iTTL = Integer.parseInt(iBinary, 16) + "";

                            System.out.println("IP: Time to live = " + iTTL + " seconds/hops\n");

                            //Protocol
                            iBinary = "";

                            iterator++;
                            iBinary += bytes[iterator];

                            iProtocol = Integer.parseInt(iBinary, 16) + "";
                            iProtocol += " (" + iProtocolList.get(Integer.parseInt(iProtocol)) + ")";

                            System.out.println("IP: Protocol = " + iProtocol + "\n");

                            //Checksum
                            iBinary = "";

                            iterator++;
                            iBinary += bytes[iterator];
                            iterator++;
                            iBinary += bytes[iterator];
                            iChecksum = iBinary;

                            System.out.println("IP: Header checksum = " + iChecksum + "\n");

                            //Source
                            iBinary = "";

                            iterator++;
                            for (int z = 0; z < 4; z++) {
                                iBinary += (z != 3) ? Integer.parseInt(bytes[iterator++], 16) + "." : Integer.parseInt(bytes[iterator++], 16);
                            }
                            iSource = iBinary;

                            System.out.println("IP: Source address = " + iSource + " ,\n");

                            //Destiny
                            iBinary = "";

                            for (int z = 0; z < 4; z++) {
                                iBinary += (z != 3) ? Integer.parseInt(bytes[iterator++], 16) + "." : Integer.parseInt(bytes[iterator], 16);
                            }
                            iDestination = iBinary;
                            System.out.println("IP: Destination address = " + iDestination + " ,\n");

                            if (Integer.parseInt(iHeaderlen) / 4 <= 5) {
                                System.out.println("IP: No options\n");
                            }

                            System.out.println("IP:\n");

                            hasFinishPayload = true;
                            hasFinishEthernet = true;
                            hasStarted = false;

                        } else if (protocol.equals("ARP")) {
                            String aBinary;

                            //Hardware Type
                            aBinary = "";
                            aBinary += bytes[iterator];
                            iterator++;
                            aBinary += bytes[iterator];

                            aHardwareType = Integer.parseInt(aBinary, 16) + "";
                            System.out.println("ARP: Hardware type = " + aHardwareType + "\n");

                            //Protocol Type
                            aBinary = "";
                            iterator++;
                            aBinary += bytes[iterator];
                            iterator++;
                            aBinary += bytes[iterator];

                            aProtocolType = aBinary;
                            System.out.println("ARP: Protocol type = " + aProtocolType);

                            switch (aProtocolType) {
                                case "0800":
                                    System.out.println("  (IP)\n");
                                    break;
                                case "0806":
                                    System.out.println(" (ARP)\n");
                                    break;
                            }

                            //Length of hardware address
                            aBinary = "";
                            iterator++;
                            aBinary += bytes[iterator];

                            aHardwareAddressLength = Integer.parseInt(aBinary, 16) + "";
                            System.out.println("ARP: Length of hardware address = " + aHardwareAddressLength + " bytes\n");

                            //Length of protocol address
                            aBinary = "";
                            iterator++;
                            aBinary += bytes[iterator];

                            aProtocolAddressLength = Integer.parseInt(aBinary, 16) + "";
                            System.out.println("ARP: Length of protocol address = " + aProtocolAddressLength + " bytes\n");

                            //Opcode
                            aBinary = "";
                            iterator++;
                            aBinary += bytes[iterator];
                            iterator++;
                            aBinary += bytes[iterator];

                            aOpcode = Integer.parseInt(aBinary, 16) + "";
                            System.out.println("ARP: Opcode " + aOpcode);

                            switch (aOpcode) {
                                case "1":
                                    System.out.println(" ARP Request\n");
                                    break;
                                case "2":
                                    System.out.println(" ARP Reply\n");
                                    break;
                            }

                            iterator++;

                            //Sender’s hardware address
                            aBinary = "";
                            for (int z = 0; z < 6; z++) {
                                aBinary += (z != 5) ? (bytes[iterator++] + ":") : bytes[iterator++];
                            }
                            aSenderHardwareAddress = aBinary;
                            System.out.println("ARP: Sender’s hardware address = " + aSenderHardwareAddress + ",\n");

                            //Sender’s protocol address
                            aBinary = "";
                            for (int z = 0; z < 4; z++) {
                                aBinary += (z != 3) ? (Integer.parseInt(bytes[iterator++], 16) + ".") : (Integer.parseInt(bytes[iterator++], 16));
                            }
                            aSenderProtocolAddress = aBinary;
                            System.out.println("ARP: Sender’s protocol address = " + aSenderProtocolAddress + "\n");

                            //Target hardware address
                            aBinary = "";
                            for (int z = 0; z < 6; z++) {
                                aBinary += (z != 5) ? (bytes[iterator++] + ":") : bytes[iterator++];
                            }
                            aTargetHardwareAddress = aBinary;
                            System.out.println("ARP: Target hardware address = " + aTargetHardwareAddress + "\n");

                            //Target protocol address
                            aBinary = "";
                            for (int z = 0; z < 4; z++) {
                                aBinary += (z != 3) ? (Integer.parseInt(bytes[iterator++], 16) + ".") : (Integer.parseInt(bytes[iterator++], 16));
                            }
                            aTargetProtocolAddress = aBinary;
                            System.out.println("ARP: Target protocol address = " + aTargetProtocolAddress + "\n");

                            iterator++;
                            //Padding
                            if (iterator < fh.capt_data) {
                                cEthernetFrame++;
                                iterator = fh.actual_length;
                            }

                            hasFinishPayload = true;
                            hasStarted = false;

                        } else if (protocol.equals("TCP")) {
                            String tBinary;

                            //Source Port      
                            tBinary = "";
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];

                            tSourcePort = Integer.parseInt(tBinary, 16) + "";
                            System.out.println("TCP: Source port = " + tSourcePort + "\n");

                            //Destination Port      
                            tBinary = "";
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];

                            tDestinationPort = Integer.parseInt(tBinary, 16) + "";
                            System.out.println("TCP: Destination port = " + tDestinationPort + "\n");

                            //Sequence Number   
                            tBinary = "";
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];

                            tSequenceNumber = Long.parseLong(tBinary, 16) + "";
                            System.out.println("TCP: Sequence number = " + tSequenceNumber + "\n");

                            //Acknowledgement Number   
                            tBinary = "";
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];

                            tAcknowledgementNumber = Long.parseLong(tBinary, 16) + "";
                            System.out.println("TCP: Acknowledgement number = " + tAcknowledgementNumber + "\n");

                            //Data Offset
                            tBinary = "";
                            iterator++;
                            tBinary += bytes[iterator];

                            tDataOffset = Integer.toBinaryString(Integer.parseInt(tBinary, 16));

                            int aux = 0;
                            while (aux < tDataOffset.length()) {
                                aux += 4;
                            }

                            tDataOffset = concatZero(tDataOffset, aux);
                            tDataOffset = 4 * Integer.parseInt(tDataOffset.substring(0, 4), 2) + "";

                            System.out.println("TCP: Data offset = " + tDataOffset + " bytes\n");

                            //Flags
                            tBinary = "";
                            iterator++;
                            tBinary += bytes[iterator];

                            tFlag = tBinary;
                            System.out.println("TCP: Flags = 0x" + tFlag + "\n");

                            tFlag = Integer.toBinaryString(Integer.parseInt(bytes[iterator], 16));
                            tFlag = concatZero(tFlag, 8);

                            for (int z = 2; z < tFlag.length(); z++) {
                                String subFlag = "";
                                if (tFlag.charAt(z) == '0') {
                                    subFlag += "No ";
                                }

                                if (z == 2) {
                                    subFlag += "urgent pointer";
                                } else if (z == 3) {
                                    subFlag += "Acknowledgement";
                                } else if (z == 4) {
                                    subFlag += "push";
                                } else if (z == 5) {
                                    subFlag += "reset";
                                } else if (z == 6) {
                                    subFlag += "Syn";
                                } else if (z == 7) {
                                    subFlag += "Fin";
                                }

                                subFlag = Character.toUpperCase(subFlag.charAt(0)) + subFlag.substring(1);

                                System.out.println("TCP: " + fragmentationDatagram(tFlag, z) + " = " + subFlag + "\n");
                            }

                            //Window 
                            tBinary = "";
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];

                            tWindow = Integer.parseInt(tBinary, 16) + "";
                            System.out.println("TCP: Window = " + tWindow + " \n");

                            //Checksum
                            tBinary = "";
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];
                            tChecksum = tBinary;

                            System.out.println("TCP: Checksum = 0x" + tChecksum + " \n");

                            ///Urgent Pointer
                            tBinary = "";
                            iterator++;
                            tBinary += bytes[iterator];
                            iterator++;
                            tBinary += bytes[iterator];
                            tUrgentPointer = Integer.parseInt(tBinary, 16) + "";

                            System.out.println("TCP: Urgent pointer = " + tUrgentPointer + " \n");

                            if (Integer.parseInt(tDataOffset) / 4 <= 5) {
                                System.out.println("TCP: No options\n");
                            }

                            //Data
                            String decryptor = "";
                            iterator++;

                            if (verifyPadding(bytes, iterator) || Integer.parseInt(tDataOffset) > 20 || calculateRange(fh.capt_data - iterator) == 0) {
                                System.out.println("TCP: Data: (first 0 bytes)\n");
                                iterator = fh.actual_length;
                                cEthernetFrame++;
                            } else {
                                System.out.println("TCP: Data: (first " + calculateRange(fh.capt_data - iterator) + " bytes)\n");
                                int currentIterator = iterator;
                                int counter = calculateRange(fh.capt_data - iterator);

                                while (iterator < currentIterator + counter) {
                                    tData = "";

                                    for (int z = 0; z < 16; z++) {
                                        if (z % 2 == 0) {
                                            tData += " ";
                                        }
                                        decryptor += bytes[iterator];
                                        tData += bytes[iterator++];
                                    }
                                    decryptor = decryptHex(decryptor);
                                    System.out.println("TCP: " + tData + " \"" + decryptor + "\"\n");
                                }
                                iterator = fh.actual_length;
                                System.out.println("TCP: \n\n");
                            }

                            hasStarted = false;
                            hasFinishEthernet = false;
                            hasFinishPayload = false;
                        } else if (protocol.equals("UDP")) {
                            String uBinary;

                            //Source Port      
                            uBinary = "";
                            uBinary += bytes[iterator];
                            iterator++;
                            uBinary += bytes[iterator];

                            uSourcePort = Integer.parseInt(uBinary, 16) + "";
                            System.out.println("UDP: Source port = " + uSourcePort + " \n");

                            //Destination Port
                            uBinary = "";
                            iterator++;
                            uBinary += bytes[iterator];
                            iterator++;
                            uBinary += bytes[iterator];

                            uDestinationPort = Integer.parseInt(uBinary, 16) + "";
                            System.out.println("UDP: Destination port = " + uDestinationPort + " \n");

                            //Length
                            uBinary = "";
                            iterator++;
                            uBinary += bytes[iterator];
                            iterator++;
                            uBinary += bytes[iterator];

                            uLength = Integer.parseInt(uBinary, 16) + "";
                            System.out.println("UDP: Length = " + uLength + " \n");

                            //Checksum
                            uBinary = "";
                            iterator++;
                            uBinary += bytes[iterator];
                            iterator++;
                            uBinary += bytes[iterator];

                            uChecksum = Integer.parseInt(uBinary, 16) + "";
                            System.out.println("UDP: Checksum = " + uChecksum + " \n");

                            //Data
                            String decryptor = "";
                            iterator++;

                            if (verifyPadding(bytes, iterator) || (fh.capt_data - iterator) < 16 || calculateRange(fh.capt_data - iterator) == 0) {
                                System.out.println("UDP: Data: (first 0 bytes)\n");
                                iterator = fh.actual_length;
                                cEthernetFrame++;
                            } else {
                                System.out.println("UDP: Data: (first " + (calculateRange(fh.capt_data - iterator)) + " bytes)\n");
                                int currentIterator = iterator;
                                int counter = calculateRange(fh.capt_data - iterator);
                                while (iterator < currentIterator + counter) {
                                    tData = "";

                                    for (int z = 0; z < 16; z++) {
                                        if (z % 2 == 0) {
                                            uData += " ";
                                        }
                                        decryptor += bytes[iterator];
                                        uData += bytes[iterator++];
                                    }
                                    decryptor = decryptHex(decryptor);
                                    System.out.println("UDP: " + uData + " \"" + decryptor + "\"\n");
                                }
                                iterator = fh.actual_length;
                                System.out.println("UDP: \n\n");
                            }

                            hasStarted = false;
                            hasFinishEthernet = false;
                            hasFinishPayload = false;

                        } else if (protocol.equals("ICMP")) {
                            String icBinary;

                            //Type      
                            icBinary = "";
                            icBinary += bytes[iterator];

                            icType = Integer.parseInt(icBinary, 16) + "";
                            System.out.println("ICMP: Type = " + icType + " \n");

                            //Code       
                            icBinary = "";
                            iterator++;
                            icBinary += bytes[iterator];

                            icCode = Integer.parseInt(icBinary, 16) + "";
                            System.out.println("ICMP: Code = " + icCode + " \n");

                            //Checksum       
                            icBinary = "";
                            iterator++;
                            icBinary += bytes[iterator];
                            iterator++;
                            icBinary += bytes[iterator];

                            iChecksum = Integer.parseInt(icBinary, 16) + "";
                            System.out.println("ICMP: Checksum = " + icChecksum + " \n");
                            System.out.println("ICMP: \n\n");

                            hasStarted = false;
                            hasFinishEthernet = false;
                            hasFinishPayload = false;
                        }
                    }
                    iterator++;
                }
                qtdquadros++;
            }
            System.out.println("ethernet frames: " + cEthernetFrame
                    + "\nethernet broadcast: " + cEthernetBroadcast
                    + "\nARP " + cARP
                    + "\nIP " + cIP
                    + "\nICMP: " + cICMP
                    + "\nUDP: " + cUDP
                    + "\nTCP: " + cTCP + "\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
