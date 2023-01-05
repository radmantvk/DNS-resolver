package ca.ubc.cs317.dnslookup;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.Set;
import java.util.*;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (Exception e) {
            closeSocket();
        }
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {

        int size = 16 + 2 + node.getHostName().length();
        // ByteBuffer buf = ByteBuffer.allocate(size);
        ByteBuffer buf = ByteBuffer.wrap(message);
        // ID
        short id = (short) random.nextInt(65535);
        buf.putShort(0, id);
    
        // Header
        // buf.putShort(1, (byte)0x00); // header line 2:  1 QR, 4bit Opcode, 1 AA, 1 TC, 1 RD  // header line 2: 1Ra, 3 Z, 4 Rcode 
        buf.put(2, (byte) 0x0);
        buf.put(3, (byte) 0x0);

        buf.put(4, (byte)0x0); //qdcount first byte
        buf.put(5, (byte) 0x1);
        
        // Answer Count - 0
        buf.put(6, (byte)0x00);
        buf.put(7, (byte)0x00);
      
        buf.put(8,(byte) 0x0); // Name server count byte 1
        buf.put(9, (byte) 0x0); // ARCount

        buf.put(10, (byte) 0x0); // ARCount
        buf.put(11, (byte) 0x0); // ARCount
        
        int sizeOfQname = node.getHostName().length() + 2;
        // Beginning of QName
        putQname(node, buf);
        
        buf.put(sizeOfQname + 12, (byte) ((node.getType().getCode() >> 4) & 0xFF)); // QTYPE
        buf.put(sizeOfQname + 13, (byte) ((node.getType().getCode()) & 0xFF)); // QTYPE
        
        buf.put(sizeOfQname + 14, (byte) 0x00);
        buf.put(sizeOfQname + 15, (byte) 0x01);

        DatagramPacket p = new DatagramPacket(message, sizeOfQname + 16, server, DEFAULT_DNS_PORT);
        socket.send(p);
        
        byte[] response = new byte[512];
        DatagramPacket responsePacket = new DatagramPacket(response, response.length);
        socket.receive(responsePacket);

        ByteBuffer responseBuffer = ByteBuffer.wrap(responsePacket.getData());

        if (verboseTracing) {
            System.out.println("\n\nQuery ID:       " + Short.toUnsignedInt(id) + " " + node.getHostName() + " " + node.getType() + " --> " + 	server.getHostAddress());
        }
        return new DNSServerResponse(responseBuffer, id);
    }

    private static void putQname(DNSNode node, ByteBuffer buf){
        int index = 12;
        String[] items = node.getHostName().split("\\.");
		 
        for (int i=0; i < items.length; i++) {
             String item = items[i];
             buf.put(index, (byte) items[i].length());
             index++;
            for (int j=0; j < item.length(); j++) {
                buf.put(index + j, (byte) ((int) item.charAt(j)));
            }
            index += item.length();
        }
        buf.put(index, (byte)0x00);
	}

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) throws IOException {                           

        Packet p = new Packet(responseBuffer, cache);
        // Set<ResourceRecord> rs = p.getRRs();
        // System.out.print(p.getRRs());
        List<ResourceRecord> ansRR = p.getAnswersRR();
        List<ResourceRecord> authRR = p.getAuthorityRR();
        List<ResourceRecord> addRR = p.getAdditionalRR();
        if (verboseTracing) {
            System.out.println("Reponse ID:     " + Short.toUnsignedInt(p.id) + " Authoritative = " + ((p.aa == 0x1)? true: false));
            System.out.println("Answers (" + ansRR.size() + ")");
            for (ResourceRecord rr: ansRR) {
                verbosePrintResourceRecord(rr, rr.getType().getCode());
             }
            
            System.out.println("Name Servers (" + authRR.size() + ")");
            for (ResourceRecord rr: authRR) {
                verbosePrintResourceRecord(rr, rr.getType().getCode());
            }

            System.out.println("Additional Information (" + addRR.size() + ")");
            for (ResourceRecord rr: addRR) {
                verbosePrintResourceRecord(rr, rr.getType().getCode());
            }
        }
        return p.getRRs();
        
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30.30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}

