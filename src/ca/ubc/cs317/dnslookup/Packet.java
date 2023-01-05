package ca.ubc.cs317.dnslookup;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.ArrayList;
import java.net.InetAddress;
import java.io.*;
// import java.util.HashSet;
import java.util.*;


public class Packet {
    public short id;
    public byte qr;
    public byte opcode;
    public byte aa;
    public byte tc;
    public byte rd;
    public byte ra;
    public byte z;
    public byte rcode;
    public short qdcount;
    public short ancount;
    public short nscount;
    public short arcount;
    public String qname = "";
    public short qtype;
    public short qclass;
    public List<ResourceRecord> answersRR = new ArrayList<>();
    public List<ResourceRecord> authorityRR= new ArrayList<>();
    public List<ResourceRecord> additionalRR= new ArrayList<>();
    public ByteBuffer buf;
    public int byteIndex = 0;
    Set<ResourceRecord> set;

   public Packet(ByteBuffer buf, DNSCache cache) throws IOException{
        this.buf = buf;
        this.id = buf.getShort(0);
        this.qr = (byte) ((buf.get(2) >> 7) & 0x1);
        this.opcode = (byte) ((buf.get(2) >> 3) & 0xF);
        this.aa = (byte) ((buf.get(2) >> 2) & 0x1);
        this.tc = (byte) ((buf.get(2) >> 1) & 0x1);
        this.rd = (byte) (buf.get(2) & 0x1);
        this.ra = (byte) ((buf.get(3) >> 7) & 0x1);
        this.z = (byte) ((buf.get(3) >> 4) & 0x7);
        this.rcode = (byte) (buf.get(3) & 0xF);
        
        this.qdcount = (short)(((short)buf.get(4) << 8) + (short) buf.get(5)); // byte 4 and 5
        
        this.ancount = (short)(((short)buf.get(6) << 8) + (short) buf.get(7)); // byte 6 and 7
        
        this.nscount = (short)(((short)buf.get(8) << 8) + (short) buf.get(9)); // byte 8 and 9
        
        this.arcount = (short)(((short)buf.get(10) << 8) + (short) buf.get(11)); // byte 4 and 5

        byteIndex = 12;
    
        this.processQNameAndGetSize();
        
        
        this.qtype = (short)(((short)buf.get(byteIndex) << 8) + (short) buf.get(byteIndex+1)); // byte 4 and 5
        byteIndex += 2;
        this.qclass = (short)(((short)buf.get(byteIndex) << 8) + (short) buf.get(byteIndex+1)); // byte 4 and 5
        byteIndex += 2;
        
        this.processRRs(cache);
   }

    // Suggestion: function takes int as index to keep byteIndex reusable for future processing
   public int processQNameAndGetSize() {
        byte substringSize = buf.get(byteIndex);
        byteIndex++;
        if (substringSize == 0x00) {
            return 0;
        }
        while (true) {
            for (int i=byteIndex; i < byteIndex+substringSize; i++) {
                 qname = qname + "" +  (char) buf.get(i);
            }
            byteIndex += substringSize;
            substringSize = buf.get(byteIndex);
            byteIndex++;
            if (substringSize == 0x00) {
                return 0;
            } 
            qname += ".";
        }  
    }

    // Helper function to process the Resource Records based on an, ns, and ar counts
    // returns: Adds new Resource Records to answersRR, authorityRR, additionalRR
    private void processRRs(DNSCache cache) throws IOException {
        // TODO: need to change HashSet into LinkedHashSet ::: Reason is that we need to maintain order in the set to have repeatable CNAME results.
        set = new LinkedHashSet<>();
        // processResponsePacket();
        for (int x = 0; x < this.ancount; x++) {
                ResourceRecord rr = processResponsePacket();
                answersRR.add(rr);
                cache.addResult(rr);
                set.add(rr);
            }
            for (int i = 0; i < this.nscount; i++){
                ResourceRecord rr = processResponsePacket();
                authorityRR.add(rr);
                cache.addResult(rr);
                set.add(rr);

            }
            for (int i = 0; i < this.arcount; i++){
                ResourceRecord rr = processResponsePacket();
                additionalRR.add(rr);
                cache.addResult(rr);
                set.add(rr);
                
            }
            
    }

    // Get the name regardless of pointer or label or combination of both ind will increment with every RR  
    private ResourceRecord processResponsePacket() throws IOException {
        String rrName = processRRName();
        short type = (short)(((short)buf.get(byteIndex) << 8) + (short) buf.get(byteIndex+1));
        RecordType rt = RecordType.getByCode(type);
        
        // RecordType rtype = rtype.RecordType(type);
        byteIndex += 2;
        short class2= (short)(((short)buf.get(byteIndex) << 8) + (short) buf.get(byteIndex+1));
        byteIndex += 2;
        int ttl = (int) (((int)buf.get(byteIndex) << 24) + ((int)buf.get(byteIndex+1) << 16) + ((int)buf.get(byteIndex+2) << 8) + (int)buf.get(byteIndex+3));
        byteIndex += 4;
        short rdlength = (short)(((short)buf.get(byteIndex) << 8) + (short) buf.get(byteIndex+1));
        byteIndex += 2;
        
        if (rt == RecordType.A || rt == RecordType.AAAA) {
            byte[] result = processInetAddress(rt);
            InetAddress addr = InetAddress.getByAddress(result);
            return new ResourceRecord(rrName, rt, (long) ttl, addr);
        } else {
            String result = processRRName();
            return new ResourceRecord(rrName, rt, ttl, result);
        }
    }
       

    private String processRRName() {
        String str = ""; 
        byte sizeOrPointer = buf.get(byteIndex);
        byteIndex++;
    
        while (true) {
            if (sizeOrPointer == (byte) 0xC0) {
                byte offset = buf.get(byteIndex);
                byteIndex++;
                str += processRRPointer(offset);
                return str;
            } else if (sizeOrPointer == 0x00) {
                return str;
            } else {
                for (int i=0; i < sizeOrPointer; i++) {
                    str = str + "" +  (char) buf.get(byteIndex + i);
                }  
                byteIndex += sizeOrPointer;
                sizeOrPointer = buf.get(byteIndex);
                byteIndex++;
                if (sizeOrPointer != 0x00) {
                    str += ".";
                }
            }
        }
    }  
    private String processRRPointer(byte offset) {
        String str = ""; 
        byte sizeOrPointer = buf.get(Byte.toUnsignedInt(offset));
        offset++;
       
        while (true) {
            if (sizeOrPointer == (byte) 0xC0) {
                byte nextOffset = buf.get(Byte.toUnsignedInt(offset));
                offset++;
                str += processRRPointer(nextOffset);
                return str;
            } else if (sizeOrPointer == 0x00) {
                return str;
            } else {
                for (int i=0; i < sizeOrPointer; i++) { //(sizeOrPointer & 0xFF)
                    str = str + "" +  (char) buf.get(Byte.toUnsignedInt(offset) + i);
                }  
                offset += sizeOrPointer;
                sizeOrPointer = buf.get(Byte.toUnsignedInt(offset));
                offset++;
                if (sizeOrPointer != 0x00) {
                    str += ".";
                }
            }
        }
    }  
        

    private byte[] processInetAddress(RecordType rt) {
        if (rt == RecordType.A) {
            byte[] ipv4 = new byte[4];
            for (int i = 0; i<4; i++) {
                ipv4[i] = buf.get(byteIndex + i);
            }
            byteIndex += 4;
            return ipv4;
        } else {          
            byte[] ipv6 = new byte[16];
            for (int i = 0; i<16; i++) {
                ipv6[i] = buf.get(byteIndex + i);
            }
            byteIndex += 16;
            return ipv6;
        }
    }
    public Set<ResourceRecord> getRRs() {
        return this.set;
    }
     public List<ResourceRecord> getAnswersRR() {
        return this.answersRR;
    }
     public List<ResourceRecord> getAuthorityRR() {
        return this.authorityRR;
    }
     public List<ResourceRecord> getAdditionalRR() {
        return this.additionalRR;
    }
    public short getID() {
        return this.id;
    }
}
