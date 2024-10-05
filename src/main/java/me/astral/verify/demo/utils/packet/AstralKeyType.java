package me.astral.verify.demo.utils.packet;

public enum AstralKeyType {
    Other((byte)2),
    Custom((byte)3),
    None((byte)98),
    ERROR((byte)99);

    private final byte type;
    AstralKeyType(Byte type){
        this.type = type;
    }

    public byte getCode() {
        return type;
    }

    public static AstralKeyType valueOf(byte type){
        for (AstralKeyType Type : AstralKeyType.values()){
            if (Type.getCode() == type){
                return Type;
            }
        }
        return ERROR;
    }
}
