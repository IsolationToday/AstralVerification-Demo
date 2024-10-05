package me.astral.verify.demo;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import me.astral.verify.demo.utils.StringUtil;
import me.astral.verify.demo.utils.packet.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;
import java.util.List;

public class CloudConfigDemo {
    //获取本地文件
    private static final String filePath = System.getProperty("user.home") + "\\Astral\\User.txt";
    private static final File userFile = new File(filePath);
    private static final String ip = "127.0.0.1";
    private static final int Port = 1145;

    public static void main(String[] args) throws IOException {
        //RSA公钥
        String k = "";
        //hwid获取
        String hwid = Base64.getEncoder().encodeToString((System.getProperty("user.name") + System.getenv("COMPUTERNAME") + System.getenv("PROCESSOR_IDENTIFIER") + System.getProperty("os.arch") + System.getProperty("os.version") + System.getProperty("user.language") + System.getenv("PROCESSOR_LEVEL") + System.getenv("PROCESSOR_REVISION") + System.getenv("PROCESSOR_IDENTIFIER") + System.getenv("PROCESSOR_ARCHITECTURE") + System.getenv("NUMBER_OF_PROCESSORS")).getBytes());

                                                                                                                    //下面是hack id
        String s = Files.readString(userFile.toPath(), StandardCharsets.UTF_8) + "\u0002" + hwid + "\u0002" + "5";
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
                                    public void channelActive(ChannelHandlerContext ctx){      //握手包                                                             所有keyType保持一致 如果是自定义加解密就Custom 不是就Other                                                         项目名称
                                        ctx.writeAndFlush(Unpooled.copiedBuffer(mergeBytes(AstralPacketBuilder.pack(new AstralPacket(AstralPacket.PROTOCOL_VERSION, AstralKeyType.Other, AstralMessageType.Handshake, AstralStatusType.Handshake, AstralPayloadType.STRING, ("Prism" + "\u0002" +hwid).getBytes(StandardCharsets.UTF_8))), "\\n\\n\\n".getBytes())));
                                    }

                                    @Override
                                    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                                        ByteBuf buf = (ByteBuf) msg;
                                        byte[] b = new byte[buf.readableBytes()];
                                        buf.readBytes(b);
                                        System.out.println("1");
                                        try {
                                            byte[] bytes = StringUtil.DECRYPT(b, k, hwid);
                                            if (bytes == null){
                                                return;
                                            }
                                            AstralPacket packet = AstralPacketBuilder.unpack(bytes);

                                            if (PacketUtil.isErrorPacket(packet)){
                                                //System.exit(0);
                                                return;
                                            }

                                            if (!PacketUtil.checkKeyType(packet, AstralKeyType.Other)){ //所有keyType保持一致 如果是自定义加解密就Custom 不是就Other
                                                //System.exit(0);
                                                return;
                                            }

                                            if (Handshake){ //可以不判断 和握手包一起发 但是要处理返回的数据包 AstralMessageType.Handshake AstralStatusType.SUCCESS AstralPayloadType.NONE
                                                if (!PacketUtil.checkPacket(packet, AstralMessageType.Handshake, AstralStatusType.SUCCESS, AstralPayloadType.NONE)) {
                                                    System.out.println("PASS");
                                                    //System.exit(0);
                                                    return;
                                                }                                                                                                                               ///所有keyType保持一致 如果是自定义加解密就Custom 不是就Other                 后面不要动
                                                ctx.writeAndFlush(Unpooled.copiedBuffer(mergeBytes(StringUtil.ENCRYPT(AstralPacketBuilder.pack(new AstralPacket(AstralPacket.PROTOCOL_VERSION, AstralKeyType.Other, AstralMessageType.User, AstralStatusType.LOGIN, AstralPayloadType.STRING, s.getBytes(StandardCharsets.UTF_8))), k, hwid), "\\n\\n\\n".getBytes())));
                                                Handshake = false;
                                            }
                                            else {

                                                //和验证类似 但云参只需要处理通过的情况 不通过并不需要崩端
                                                if (PacketUtil.checkPacket(packet, AstralMessageType.SERVER, AstralStatusType.SUCCESSConfig, AstralPayloadType.BYTEARRAY)){
                                                    //packet.payload 就是参的Bytes
                                                    byte[] configByteArray=packet.payload;

                                                    List<String> list = new String(configByteArray, StandardCharsets.UTF_8).lines().toList(); //例如Alien NullPoint
                                                    for (String s2 : list) {
                                                        /* nullpoint config loader demo:
                                                        try {
                                                            Iterator<String> iterator = COLON_SPLITTER.limit(2).split(s2).iterator();
                                                            settings.put(iterator.next(), iterator.next());
                                                        } catch (Exception var10) {
                                                            System.out.println("Skipping bad option: " + s2);
                                                        }*/
                                                    }
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
