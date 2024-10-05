package me.astral.verify.demo;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import me.astral.verify.demo.utils.packet.*;
import me.astral.verify.demo.utils.StringUtil;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

public class VerifyDemo {
    //获取本地文件
    private static final String filePath = System.getProperty("user.home") + "\\Astral\\User.txt";
    private static final File userFile = new File(filePath);
    private static final String ip = "127.0.0.1";
    private static final int Port = 1145;
    public static final String hackID="114514";
    public static final String rsaKey= " ";

    public static void main(String[] args) throws IOException {
        //RSA公钥
        //hwid获取
        String hwid = Base64.getEncoder().encodeToString((System.getProperty("user.name") + System.getenv("COMPUTERNAME") + System.getenv("PROCESSOR_IDENTIFIER") + System.getProperty("os.arch") + System.getProperty("os.version") + System.getProperty("user.language") + System.getenv("PROCESSOR_LEVEL") + System.getenv("PROCESSOR_REVISION") + System.getenv("PROCESSOR_IDENTIFIER") + System.getenv("PROCESSOR_ARCHITECTURE") + System.getenv("NUMBER_OF_PROCESSORS")).getBytes());



        String s = Files.readString(userFile.toPath(), StandardCharsets.UTF_8) + "\u0002" + hwid + "\u0002" + hackID;
        EventLoopGroup group = new NioEventLoopGroup();
        new Thread(() -> { //如果要等待就不要Thread
            try {
                Bootstrap b = new Bootstrap();
                b.group(group)
                        .channel(NioSocketChannel.class)
                        .handler(new ChannelInitializer<SocketChannel>() {
                            @Override
                            public void initChannel(SocketChannel ch) {
                                //防粘包半包
                                ch.pipeline().addLast(new DelimiterBasedFrameDecoder(65535, Unpooled.copiedBuffer("\\n\\n\\n".getBytes())));
                                ch.pipeline().addLast(new ChannelInboundHandlerAdapter(){
                                    boolean Handshake = true;
                                    @Override
                                    public void channelActive(ChannelHandlerContext ctx){      //握手包                                                             所有keyType保持一致 如果是自定义加解密就Custom 不是就Other                                                                                 项目名称
                                        ctx.writeAndFlush(Unpooled.copiedBuffer(mergeBytes(AstralPacketBuilder.pack(new AstralPacket(AstralPacket.PROTOCOL_VERSION, AstralKeyType.Other, AstralMessageType.Handshake, AstralStatusType.Handshake, AstralPayloadType.STRING, ("Prism" + "\u0002" +hwid).getBytes(StandardCharsets.UTF_8))), "\\n\\n\\n".getBytes())));
                                    }

                                    @Override
                                    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                                        ByteBuf buf = (ByteBuf) msg;
                                        byte[] b = new byte[buf.readableBytes()];
                                        buf.readBytes(b);
                                        try {
                                            byte[] bytes = StringUtil.DECRYPT(b, rsaKey, hwid);
                                            if (bytes == null){
                                                System.exit(0); //注意这里使用System.exit(0);并不安全 它可被拦截 到实际使用推荐使用别的方法崩溃jvm
                                                return;
                                            }

                                            AstralPacket packet = AstralPacketBuilder.unpack(bytes);

                                            if (PacketUtil.isErrorPacket(packet)){
                                                System.exit(0);
                                                return;
                                            }

                                            if (!PacketUtil.checkKeyType(packet, AstralKeyType.Other)){ //所有keyType保持一致 如果是自定义加解密就Custom 不是就Other
                                                System.exit(0);
                                                return;
                                            }

                                            if (Handshake){ //可以不判断 和握手包一起发 但是要处理返回的数据包 AstralMessageType.Handshake AstralStatusType.SUCCESS AstralPayloadType.NONE
                                                if (!PacketUtil.checkPacket(packet, AstralMessageType.Handshake, AstralStatusType.SUCCESS, AstralPayloadType.NONE)) {
                                                    System.exit(0);
                                                    return;
                                                }                                                                                                                                 ///所有keyType保持一致 如果是自定义加解密就Custom 不是就Other                 后面不要动
                                                ctx.writeAndFlush(Unpooled.copiedBuffer(mergeBytes(StringUtil.ENCRYPT(AstralPacketBuilder.pack(new AstralPacket(AstralPacket.PROTOCOL_VERSION, AstralKeyType.Other, AstralMessageType.User, AstralStatusType.LOGIN, AstralPayloadType.STRING, s.getBytes(StandardCharsets.UTF_8))), rsaKey, hwid), "\\n\\n\\n".getBytes())));
                                                Handshake = false;
                                            }
                                            else {
                                                if (!PacketUtil.checkMessageType(packet, AstralMessageType.SERVER)){
                                                    System.exit(0);
                                                    return;
                                                }

                                                if (PacketUtil.checkStatusType(packet, AstralStatusType.SUCCESS)){
                                                   System.out.println("PASS");
                                                    //成功
                                                    if (PacketUtil.checkPayloadType(packet, AstralPayloadType.STRING)){
                                                        String string = new String(packet.payload, StandardCharsets.UTF_8); //推荐转码中全部使用UTF-8 否则中文会乱码
                                                        //有返回值
                                                    } else {
                                                        //无返回值
                                                        //下面以此类推
                                                    }
                                                }
                                                else if (PacketUtil.checkStatusType(packet, AstralStatusType.WRONG)){
                                                    //失败
                                                    if (PacketUtil.checkPayloadType(packet, AstralPayloadType.STRING)){
                                                        String string = new String(packet.payload, StandardCharsets.UTF_8);

                                                    } else {

                                                    }
                                                    System.exit(0);
                                                }
                                                else if (PacketUtil.checkStatusType(packet, AstralStatusType.BLOCK)){
                                                    //封禁
                                                    if(PacketUtil.checkPayloadType(packet, AstralPayloadType.STRING)){
                                                        String string = new String(packet.payload, StandardCharsets.UTF_8);

                                                    } else {

                                                    }
                                                    System.exit(0);
                                                }
                                                else {
                                                    System.exit(0);
                                                }
                                            }
                                        } finally {
                                            buf.release();
                                        }
                                    }

                                    @Override
                                    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                                        ctx.close();
                                    }

                                });
                            }
                        });

                ChannelFuture f = b.connect(ip, Port).sync();

                f.channel().closeFuture().sync();
            } catch (Exception e) {
                //抓异常崩溃包括网络无连接等
                System.exit(0);
            } finally {
                group.shutdownGracefully();
            }
        }).start();
    }

    public static byte[] mergeBytes(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}