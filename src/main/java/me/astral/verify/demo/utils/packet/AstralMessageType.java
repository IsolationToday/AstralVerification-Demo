package me.astral.verify.demo.utils.packet;

public enum AstralMessageType {
    User((byte)2),
    Handshake((byte)3),
    SERVER((byte)98),
    ERROR((byte) 99);
    private final byte type;
    AstralMessageType(Byte type){
        this.type = type;
    }

    public byte getType() {
        return type;
    }

    public static AstralMessageType valueOf(byte type){
        for (AstralMessageType messageType : AstralMessageType.values()){
            if (messageType.getType() == type){
                return messageType;
            }
        }
        return ERROR;
    }
}
