# AstralVerification Demo
ͨ����ʾ��������Կ��ٽ̻�����ν������֤/�Ʋ���Ŀ�Խӵ�AstralVerification

[��֤ʾ�� VerifyDemo.java](src/main/java/me/astral/verify/demo/VerifyDemo.java)<br/>
[�Ʋ�ʾ�� CloudConfigDemo.java](src/main/java/me/astral/demo/verify/CloudConfigDemo.java)

__����Խ�[utils�ļ���](src/main/java/me/astral/verify/demo/utils)ȫ�������������Ŀ�ڣ���������AstralVerification���������������__

***

## �Զ������/����
AstralVerificationϵͳ֧���û��Զ�����Ŀ�ĵڶ��ؼ��ܽ����㷨

������Զ�������㷨����һ������������,�������㷨���������Ϊencrypt,�������Ϊbyte[],���Ϊbyte[]�ĺ����У�ʾ��:
```java
public static byte[] encrypt(byte[] bytes) {
    byte[] encrypted = new byte[bytes.length];
    for (int i = 0; i < bytes.length; ++i) {
        encrypted[i] = (byte)(bytes[i] ^ 114514);
    }
    return encrypted;
}

```

������Զ�������㷨����һ������������,�������㷨���������Ϊdecrypt,�������Ϊbyte[],���Ϊbyte[]�ĺ����У�ʾ��:
```java
public static byte[] decrypt(byte[] bytes) {
    byte[] decrypted = new byte[bytes.length];
    for (int i = 0; i < bytes.length; ++i) {
        encrypted[i] = (byte)(bytes[i] ^ 114514);
    }
    return decrypted;
}

```

�ڱ�д��Ϻ�,ʹ������`javac xxxx.java`����ļ���/�����㷨����Ϊ.class�ļ�����������.class�ļ����͸�AstralVerification�����ߡ�

***�벻Ҫ�ټ���/�����㷨�ļ��м����ǿ�Ļ���������Ĵ��룬���ǲ�������Щ��Ϊ���ܻᵼ������Զ����㷨�޷�ͨ����ˡ�***



