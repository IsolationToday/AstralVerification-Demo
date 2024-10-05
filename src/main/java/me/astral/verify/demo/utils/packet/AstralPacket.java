package me.astral.verify.demo.utils.packet;

public class AstralPacket {
    public static Byte PROTOCOL_VERSION = 11;
    public int version;
    public AstralKeyType keyType;
    public AstralMessageType msgType;
    public AstralStatusType statusType;
    public AstralPayloadType payloadType;
    public byte[] payload;
    public AstralPacket(int version, AstralKeyType keyType, AstralMessageType msgType, AstralStatusType statusType, AstralPayloadType payloadType, byte[] payload){
        this.version = version;
        this.keyType = keyType;
        this.msgType = msgType;
        this.statusType = statusType;
        this.payloadType = payloadType;
        this.payload = payload;
    }

}
