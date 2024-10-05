package me.astral.verify.demo.utils.packet;

public enum AstralPayloadType {
    BYTEARRAY((byte) 0),
    STRING((byte)1),
    NONE((byte)2);

    private final byte type;
    AstralPayloadType(Byte type){
        this.type = type;
    }

    public byte getType() {
        return type;
    }

    public static AstralPayloadType valueOf(byte type){
        for (AstralPayloadType Type : AstralPayloadType.values()){
            if (Type.getType() == type){
                return Type;
            }
        }
        return NONE;
    }
}
