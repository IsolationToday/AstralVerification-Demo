package me.astral.verify.demo.utils.packet;

import java.util.Arrays;

public class AstralPacketBuilder {
    public static byte[] pack(AstralPacket pkt) {
        byte[] b = new byte[]{88, 77, (byte) pkt.version, pkt.keyType.getCode(), pkt.msgType.getType(), pkt.statusType.getCode(), pkt.payloadType.getType()};
        if (pkt.payload != null) {
            b = Arrays.copyOf(b, b.length + pkt.payload.length);
            System.arraycopy(pkt.payload, 0, b, b.length - pkt.payload.length, pkt.payload.length);
        }
        return b;
    }

    public static AstralPacket unpack(byte[] bytes){
        if(bytes[0] == 88 && bytes[1] == 77 && bytes.length >= 7){
            if(bytes[2] == AstralPacket.PROTOCOL_VERSION){
                if(bytes[6] == AstralPayloadType.NONE.getType()){
                    return new AstralPacket(
                            bytes[2],                            //Protocol Version
                            AstralKeyType.valueOf(bytes[3]),     //KeyType
                            AstralMessageType.valueOf(bytes[4]), //Message Type
                            AstralStatusType.valueOf(bytes[5]),  //Status Code
                            AstralPayloadType.NONE,              //Payload Type
                            null);
                }
                byte[] packetPayload = Arrays.copyOfRange(bytes, 7, bytes.length);
                return new AstralPacket(
                        bytes[2],                            //Protocol Version
                        AstralKeyType.valueOf(bytes[3]),     //KeyType
                        AstralMessageType.valueOf(bytes[4]), //Message Type
                        AstralStatusType.valueOf(bytes[5]),  //Status Code
                        AstralPayloadType.valueOf(bytes[6]), //Payload Type
                        packetPayload);
            }
            return new AstralPacket(bytes[2], AstralKeyType.ERROR, AstralMessageType.ERROR, AstralStatusType.ERROR, AstralPayloadType.NONE, null);
        }
        return new AstralPacket(AstralPacket.PROTOCOL_VERSION, AstralKeyType.ERROR, AstralMessageType.ERROR, AstralStatusType.ERROR, AstralPayloadType.NONE, null);
    }
}
