package me.astral.verify.demo.utils.packet;

public class PacketUtil {
    public static boolean checkPacket(AstralPacket packet, AstralKeyType keyType, AstralMessageType msgType, AstralStatusType statusType, AstralPayloadType payloadType){
        if (packet == null) return false;
        return packet.version == AstralPacket.PROTOCOL_VERSION && packet.keyType == keyType && packet.msgType == msgType && packet.statusType == statusType && packet.payloadType == payloadType;
    }

    public static boolean checkPacket(AstralPacket packet, AstralMessageType msgType, AstralStatusType statusType, AstralPayloadType payloadType){
        if (packet == null) return false;
        return packet.version == AstralPacket.PROTOCOL_VERSION && packet.msgType == msgType && packet.statusType == statusType && packet.payloadType == payloadType;
    }
    public static boolean checkPacket(AstralPacket packet, AstralMessageType msgType, AstralStatusType statusType){
        if (packet == null) return false;
        return packet.version == AstralPacket.PROTOCOL_VERSION && packet.msgType == msgType && packet.statusType == statusType;
    }

    public static boolean checkStatusType(AstralPacket packet, AstralStatusType statusType){
        if (packet == null) return false;
        return packet.statusType == statusType;
    }

    public static boolean checkMessageType(AstralPacket packet, AstralMessageType messageType){
        if (packet == null) return false;
        return packet.msgType == messageType;
    }

    public static boolean checkKeyType(AstralPacket packet, AstralKeyType keyType){
        if (packet == null) return false;
        return packet.keyType == keyType;
    }
    public static boolean checkPayloadType(AstralPacket packet, AstralPayloadType payloadType){
        if (packet == null) return false;
        return packet.payloadType == payloadType && packet.payload != null;
    }

    public static boolean isErrorPacket(AstralPacket packet){
        if (packet == null) return true;
        return  packet.keyType == AstralKeyType.ERROR || packet.msgType == AstralMessageType.ERROR || packet.statusType == AstralStatusType.ERROR;
    }
}
