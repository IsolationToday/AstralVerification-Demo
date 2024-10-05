package me.astral.verify.demo.utils.packet;

public enum AstralStatusType {
    SUCCESS((byte)0),
    SUCCESSConfig((byte)1),
    WRONG((byte)2),
    BLOCK((byte)3),

    LOGIN((byte)31),
    CheckVersion((byte)35),
    UserFileDecrypt((byte)36),



    Handshake((byte)97),
    ERROR((byte)99);

    private final byte type;
    AstralStatusType(Byte type){
        this.type = type;
    }

    public byte getCode() {
        return type;
    }

    public static AstralStatusType valueOf(byte type){
        for (AstralStatusType Type : AstralStatusType.values()){
            if (Type.getCode() == type){
                return Type;
            }
        }
        return ERROR;
    }
}
