package cn.comein.test.api;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author 廖仑辉
 * @date 10/12/2021 4:38 PM
 */

public class testRSA {

    //仅供示例，为确保安全，请生成自己的密钥对
    String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIhphUndfouOZGT0GpGQjr9Omg0kg/etboTcBUrTFjSwwQtvNa2nBYMzT9W57s1f3lzSHap9RD+Rt7Duml+D4k/fW52UP1Krxqt8FF5/TPuCLa20hCpA9CvAvS33+C8dC7fWW14gqHKc7nQCCkkLTP1f7XpKDGGoDbhPi6VHji6jAgMBAAECgYAfSUxXt6RJb7wY51+cmTIUMHvmncRirvVVJX1VPvqt1QhBjh0amd8Ky175Hu7lTaKbWVmSe66Gge5Gd0MSuxXRcF1WKLa76Qu5wVbFyAXlOacYvSrNhmmyKNJBs1W30nxanvogsS8pq74ljUtcjZofLJZIDoiEy3RLKMPmRxHj0QJBAPtkFZW+aFA7igftjXWeHhVj1mBazFccfOdm0SBsBaH0IqsTTVuDPYrhaGvrMNBieA5a7tQghLLy+xNnBLV1LTkCQQCK6cclXwd8MvHzrJ0cw4lzUrMHu28YMsqnDanZJC6nqRSpN2oT6xkxDSR2PXKDuy1WyxhmMQW21f1f22iA7Va7AkEAvuFVymfTiOhMfIyRlrdCnHc8Ndl7wsEszf+x1u5usHRRRpjXah8Swbs5sIfafr/l7PB627L9T2tT3X2hg66/cQJAVGycIbRNgkgcEDI6Ej8sjDAYqnxZmmVUEI8XSObai/8QlX8eMxjQ6KTKIipaLIFXnsYz//ePN316TgW0z5Zu/QJBALQQ6P7oiAb8Xx8c7XV+zsjm/Ypsfd/mvXo5rBFwAhFq+EZ+VrPntTpDpNxn9frdllsDPLrpfJGgKsbRCVzng24=";
    String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIaYVJ3X6LjmRk9BqRkI6/TpoNJIP3rW6E3AVK0xY0sMELbzWtpwWDM0/Vue7NX95c0h2qfUQ/kbew7ppfg+JP31udlD9Sq8arfBRef0z7gi2ttIQqQPQrwL0t9/gvHQu31lteIKhynO50AgpJC0z9X+16SgxhqA24T4ulR44uowIDAQAB";

    String example = "J5riBg2k9S+5tYUfHErFGR5xpH4Nb2VZfRstuse9VNKwc3BlDbnr0Fcvs8hWVK1bEN5vfPgRyk971CeAChpAq7ekVJWe1qCLqdDTvetdqWE2/0z+FSozcwRCwlscruW+S7HCo06aMV4Qv/9yaBPdsXT80FUpWiQHMTjYVdJ3LlA=";

    long timestamp = System.currentTimeMillis();
    String openid = UUID.randomUUID().toString();
    String phone = "61575515";
    String areaCode = "+852";
    String email = "name@example.com";

    @Test
    public void generateKeyPair() {
        RSA rsa = new RSA();
        System.out.println("PrivateKeyBase64:" + rsa.getPrivateKeyBase64());
        System.out.println("PublicKeyBase64:" + rsa.getPublicKeyBase64());
    }

    @Test
    public void minimalUserinfoEncrypt() {
        String openid = UUID.randomUUID().toString();
        long timestamp = System.currentTimeMillis();
        String userinfo = "{\"openid\":\"" + openid + "\",\"timestamp\":\"" + timestamp + "\"}";
        System.out.println("userinfo:" + userinfo);
        RSA rsa = new RSA(privateKey, null);
        byte[] encrypt2 = rsa.encrypt(StrUtil.bytes(userinfo, CharsetUtil.CHARSET_UTF_8), KeyType.PrivateKey);
        String encode = Base64.encode(encrypt2);
        System.out.println("encryptedUserInfo:" + encode);
    }


    @Test
    public void decryptExample() {
        RSA rsa = new RSA(null, publicKey);
        byte[] decode = Base64.decode(example);
        byte[] decrypt = rsa.decrypt(decode, KeyType.PublicKey);
        String s = new String(decrypt);
        System.out.println(s);
    }


    @Test
    public void FullUserInfoEncryptExample() {
        String openid = UUID.randomUUID().toString();
        long timestamp = System.currentTimeMillis();
        String userinfo = "{\"openid\":\"" + openid + "\",\"email\":\"" + email + "\",\"phone\":\"" + phone + "\",\"areaCode\":\"" + areaCode + "\",\"timestamp\":\"" + timestamp + "\"}";
        System.out.println("userinfo:" + userinfo);
        RSA rsa = new RSA(privateKey, null);
        byte[] encrypt2 = rsa.encrypt(StrUtil.bytes(userinfo, CharsetUtil.CHARSET_UTF_8), KeyType.PrivateKey);
        String encode = Base64.encode(encrypt2);
        System.out.println("encryptedUserInfo:" + encode);
    }



    @Test
    public void encrypt() {
        RSA rsaWithPrivateKey = new RSA(privateKey, null);
        RSA rsaWithPublicKey = new RSA(null, publicKey);


        String userinfo = "{\"openid\":\"" + openid + "\",\"email\":\"" + email + "\",\"phone\":\"" + phone + "\",\"areaCode\":\"" + areaCode + "\",\"timestamp\":\"" + timestamp + "\"}";
        System.out.println("userinfo:" + userinfo);
//公钥加密，私钥解密
        String text = userinfo;
        byte[] encrypt = rsaWithPublicKey.encrypt(StrUtil.bytes(text, CharsetUtil.CHARSET_UTF_8), KeyType.PublicKey);

        byte[] decrypt = rsaWithPrivateKey.decrypt(encrypt, KeyType.PrivateKey);


        assertEquals(text, StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8));

//私钥加密，公钥解密
        byte[] encrypt2 = rsaWithPrivateKey.encrypt(StrUtil.bytes(text, CharsetUtil.CHARSET_UTF_8), KeyType.PrivateKey);
        String encode = Base64.encode(encrypt2);

        System.out.println(encode);
        byte[] decode = Base64.decode(encode);

        byte[] decrypt2 = rsaWithPublicKey.decrypt(decode, KeyType.PublicKey);
        String decrypted = StrUtil.str(decrypt2, CharsetUtil.CHARSET_UTF_8);

        assertEquals(text, decrypted);
    }
}
