package org.example.aesutil;

import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESUtils{
    private static String DECRYPTAUTH = "3333";

    /**
     * 生成一个对称的加密密钥，可以指定固定密码
     * @return
     */
    public static String createKey(){
        try {
            // 生成key
            KeyGenerator keyGenerator;
            //构造密钥生成器，指定为AES算法,不区分大小写
            keyGenerator = KeyGenerator.getInstance("AES");
            //生成一个128位的随机源,根据传入的字节数组
            keyGenerator.init(128);
            //产生原始对称密钥
            SecretKey secretKey = keyGenerator.generateKey();
            //获得原始对称密钥的字节数组
            byte[] keyBytes = secretKey.getEncoded();
            // key转换,根据字节数组生成AES密钥
            return parseByte2HexString(keyBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * 加密的方法
     * @param content 加密的字符串
     * @return
     */
    public static String encrypt(String content){
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");    // 创建AES的Key生产者
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(DECRYPTAUTH.getBytes());
            kgen.init(128, random);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded(); // 返回基本编码格式的密钥，如果此密钥不支持编码，则返回
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");// 转换为AES专用密钥
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            byte[] byteContent = content.getBytes("utf-8");
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化为加密模式的密码器
            byte[] result = cipher.doFinal(byteContent);// 加密
            return new String(Base64.encodeBase64(result));
        } catch (Exception e) {
            System.out.println("加密失败：msg={}" + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 解密
     * @param content
     * @return
     */
    public static String decrypt(String content){
        try {
            KeyGenerator deKgen = KeyGenerator.getInstance("AES");// 创建AES的Key生产者
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(DECRYPTAUTH.getBytes());
            deKgen.init(128, random);
            SecretKey secretKey = deKgen.generateKey();// 根据用户密码，生成一个密钥
            byte[] enCodeFormat = secretKey.getEncoded();// 返回基本编码格式的密钥
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");// 转换为AES专用密钥
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化为解密模式的密码器
            byte[] deBase64Content = Base64.decodeBase64(content);
            byte[] result = cipher.doFinal(deBase64Content);
            return new String(result, "utf-8");
        } catch (Exception e) {
            System.out.println("解密失败：msg={}" + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }
    /**将二进制转换成16进制
     * @param buf
     * @return
     */
    public static String parseByte2HexString(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }
    /**将16进制转换为二进制
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length()/2];
        for (int i = 0;i< hexStr.length()/2; i++) {
            int high = Integer.parseInt(hexStr.substring(i*2, i*2+1), 16);
            int low = Integer.parseInt(hexStr.substring(i*2+1, i*2+2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }
    public static void main(String[] args) {
        String sourceText = "haha";
        System.out.println("原始数据是：" + sourceText);
        String privateKeyEncode = encrypt(sourceText);
        System.out.println("加密后的数据是：" + privateKeyEncode);
        String decPw = decrypt(privateKeyEncode);
        System.out.println("解密之后的数据为：" + decPw);
    }
}
