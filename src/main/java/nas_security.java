import java.nio.ByteBuffer;
import java.util.Arrays;

public class NasMessageHandler {
    
    public static byte[] encapNasMsgToEnvelope(byte[] nasPDU) {
        // According to TS 24.502 8.2.4 and 9.4
        // NAS message envelope = Length | NAS Message
        ByteBuffer buffer = ByteBuffer.allocate(2 + nasPDU.length);
        buffer.putShort((short) nasPDU.length);
        buffer.put(nasPDU);
        return buffer.array();
    }

    public static byte[] NASEncode(RanUeContext ue, NasMessage msg, boolean securityContextAvailable, boolean newSecurityContext) throws Exception {
        if (ue == null) throw new Exception("amfUe is null");
        if (msg == null) throw new Exception("Nas Message is empty");
        
        byte sequenceNumber;
        byte[] payload;
        
        if (!securityContextAvailable) {
            return msg.plainNasEncode();
        } else {
            if (newSecurityContext) {
                ue.ULCount.set(0, 0);
                ue.DLCount.set(0, 0);
            }
            
            sequenceNumber = ue.ULCount.SQN();
            payload = msg.plainNasEncode();
            
            if (msg.securityHeader.getSecurityHeaderType() != NasSecurityHeaderType.INTEGRITY_PROTECTED &&
                msg.securityHeader.getSecurityHeaderType() != NasSecurityHeaderType.PLAIN_NAS) {
                Security.nasEncrypt(ue.cipheringAlg, ue.knasEnc, ue.ULCount.get(), ue.getBearerType(),
                    Security.Direction.UPLINK, payload);
            }
            
            payload = prependByte(payload, sequenceNumber);
            byte[] mac32 = Security.nasMacCalculate(ue.integrityAlg, ue.knasInt, ue.ULCount.get(), ue.getBearerType(),
                    Security.Direction.UPLINK, payload);
            
            payload = prependBytes(payload, mac32);
            
            byte[] msgSecurityHeader = new byte[]{msg.securityHeader.getProtocolDiscriminator(), msg.securityHeader.getSecurityHeaderType()};
            payload = prependBytes(payload, msgSecurityHeader);
            
            ue.ULCount.addOne();
        }
        return payload;
    }
    
    public static byte[] NASDecode(RanUeContext ue, int securityHeaderType, byte[] payload) throws Exception {
        if (ue == null) throw new Exception("amfUe is null");
        if (payload == null) throw new Exception("Nas payload is empty");
        
        NasMessage msg = new NasMessage();
        msg.securityHeaderType = (byte) (NasMessage.getSecurityHeaderType(payload) & 0x0F);
        
        if (securityHeaderType == NasSecurityHeaderType.PLAIN_NAS) {
            msg.plainNasDecode(payload);
            return msg.getPayload();
        } else if (ue.integrityAlg == Security.AlgIntegrity128NIA0) {
            payload = Arrays.copyOfRange(payload, 3, payload.length);
            Security.nasEncrypt(ue.cipheringAlg, ue.knasEnc, ue.DLCount.get(), ue.getBearerType(),
                Security.Direction.DOWNLINK, payload);
            msg.plainNasDecode(payload);
            return msg.getPayload();
        } else {
            byte[] securityHeader = Arrays.copyOfRange(payload, 0, 6);
            byte sequenceNumber = payload[6];
            byte[] receivedMac32 = Arrays.copyOfRange(securityHeader, 2, 6);
            
            payload = Arrays.copyOfRange(payload, 6, payload.length);
            
            byte[] mac32 = Security.nasMacCalculate(ue.integrityAlg, ue.knasInt, ue.DLCount.get(), ue.getBearerType(),
                    Security.Direction.DOWNLINK, payload);
            
            if (!Arrays.equals(mac32, receivedMac32)) {
                throw new Exception("NAS MAC verification failed");
            }
            
            payload = Arrays.copyOfRange(payload, 1, payload.length);
            Security.nasEncrypt(ue.cipheringAlg, ue.knasEnc, ue.DLCount.get(), ue.getBearerType(),
                Security.Direction.DOWNLINK, payload);
            
            msg.plainNasDecode(payload);
            return msg.getPayload();
        }
    }
    
    private static byte[] prependByte(byte[] data, byte b) {
        byte[] newData = new byte[data.length + 1];
        newData[0] = b;
        System.arraycopy(data, 0, newData, 1, data.length);
        return newData;
    }
    
    private static byte[] prependBytes(byte[] data, byte[] prefix) {
        byte[] newData = new byte[data.length + prefix.length];
        System.arraycopy(prefix, 0, newData, 0, prefix.length);
        System.arraycopy(data, 0, newData, prefix.length, data.length);
        return newData;
    }
}
