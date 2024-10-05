# AstralVerification Demo
通过此示例程序可以快速教会你如何将你的验证/云参项目对接到AstralVerification

[验证示例 VerifyDemo.java](src/main/java/me/astral/verify/demo/VerifyDemo.java)<br/>
[云参示例 CloudConfigDemo.java](src/main/java/me/astral/demo/verify/CloudConfigDemo.java)

__你可以将[utils文件夹](src/main/java/me/astral/verify/demo/utils)全部拷贝至你的项目内，以用于向AstralVerification服务器发送请求包__

***

## 自定义加密/解密
AstralVerification系统支持用户自定义项目的第二重加密解密算法

将你的自定义加密算法放入一个单独的类中,将加密算法主体放入名为encrypt,输入参数为byte[],输出为byte[]的函数中，示例:
```java
public static byte[] encrypt(byte[] bytes) {
    byte[] encrypted = new byte[bytes.length];
    for (int i = 0; i < bytes.length; ++i) {
        encrypted[i] = (byte)(bytes[i] ^ 114514);
    }
    return encrypted;
}

```

将你的自定义解密算法放入一个单独的类中,将解密算法主体放入名为decrypt,输入参数为byte[],输出为byte[]的函数中，示例:
```java
public static byte[] decrypt(byte[] bytes) {
    byte[] decrypted = new byte[bytes.length];
    for (int i = 0; i < bytes.length; ++i) {
        encrypted[i] = (byte)(bytes[i] ^ 114514);
    }
    return decrypted;
}

```

在编写完毕后,使用命令`javac xxxx.java`将你的加密/解密算法编译为.class文件，将编译后的.class文件发送给AstralVerification开发者。

***请不要再加密/解密算法文件中加入较强的混淆，刁钻的代码，或是病毒。这些行为可能会导致你的自定义算法无法通过审核。***



