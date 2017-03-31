package com.bank.webservice;

import java.security.Key;  
import java.security.KeyFactory;  
import java.security.KeyPair;  
import java.security.KeyPairGenerator;  
import java.security.PrivateKey;  
import java.security.PublicKey;  
import java.security.SecureRandom;  
import java.security.Signature;  
import java.security.interfaces.DSAPrivateKey;  
import java.security.interfaces.DSAPublicKey;  
import java.security.spec.PKCS8EncodedKeySpec;  
import java.security.spec.X509EncodedKeySpec;  
import java.util.HashMap;  
import java.util.Map;  
  
import sun.misc.BASE64Decoder;  
import sun.misc.BASE64Encoder;  
/*** 
 * 签名验签算法:DSA 
 * 1、生成密钥对 
 * 2、签名 
 * 3、验签 
 * @author xgh 
 * 
 */  
public class DSASignaureUtil{  
     public static final String  Algorithm_DSA="DSA";  
     //默认密钥字节数  
     private static final int key_size=1024;  
     //默认种子  
     public static final String default_seed="0f22507a10bbddd07d8a3082122966e3";  
       
     public static final String public_key = "DSAPublicKey";  
     public static final String private_key = "DSAPrivateKey";  
       
     /*** 
      * 生成密钥种子 
      * @param seed 
      * @return 
      * @throws Exception 
      */  
     public static Map initKey(String seed) throws Exception{  
         KeyPairGenerator keygen = KeyPairGenerator.getInstance(Algorithm_DSA);  
        //　初始化随机产生器  
        SecureRandom secureRandom = new SecureRandom();  
        secureRandom.setSeed(seed.getBytes());  
        keygen.initialize(key_size,secureRandom);  
        KeyPair keys = keygen.genKeyPair();  
        DSAPublicKey publicKey = (DSAPublicKey) keys.getPublic();  
        DSAPrivateKey privateKey = (DSAPrivateKey) keys.getPrivate();  
        Map map = new HashMap(2);  
        map.put(public_key,publicKey);  
        map.put(private_key,privateKey);  
          
         return map;  
     }  
       
       
     /*** 
      * 用私钥对信息生成数字签名 
      * @param data 加密数据 
      * @param privateKey 私钥 
      * @return 
      * @throws Exception 
      */  
     public static String sign(byte[] data,String privateKey)throws Exception{  
        //　解密由base64编码的私钥  
        byte[] keyBytes = decryptBASE64(privateKey);  
        //　构造PKCS8EncodedKeySpec对象  
        //PKCS#8:描述私有密钥信息格式，该信息包括公开密钥算法的私有密钥以及可选的属性集等[27]。  
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
        //　KEY_ALGORITHM　指定的加密算法  
        KeyFactory keyFactory = KeyFactory.getInstance(Algorithm_DSA);  
        //　取私钥匙对象  
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);  
        //用私钥对信息生成数字签名   
        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());  
        signature.initSign(priKey);  
        signature.update(data);  
  
        return encryptBASE64(signature.sign());  
     }  
       
     /*** 
      * 校验数字签名 
      * @param data 加密数据 
      * @param publicKey 公钥 
      * @param sign 数据签名 
      * @return 校验成功返回true　失败返回false 
      * @throws Exception 
      */  
     public static boolean verify(byte[] data,String publicKey,String sign) throws Exception {  
        // 　解密由base64编码的公钥  
        byte[] keyBytes = decryptBASE64(publicKey);  
        // 　构造X509EncodedKeySpec对象  
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
        // 　ALGORITHM　指定的加密算法  
        KeyFactory keyFactory = KeyFactory.getInstance(Algorithm_DSA);  
        // 　取公钥匙对象  
        PublicKey pubKey = keyFactory.generatePublic(keySpec);  
        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());  
        signature.initVerify(pubKey);  
        signature.update(data);  
        // 　验证签名是否正常  
        return signature.verify(decryptBASE64(sign));  
     }  
  
      
     /*** 
      * 默认生成密钥 
      * @return 
      * @throws Exception 
      */  
     public static Map initKey() throws Exception {  
         return initKey(default_seed);  
     }  
       
      
     /*** 
      * 取得私钥 
      * @param keyMap 
      * @return 
      * @throws Exception 
      */  
     public static String getPrivateKey(Map keyMap)throws Exception {  
         Key key = (Key) keyMap.get(private_key);  
         return encryptBASE64(key.getEncoded());  
     }  
  
     /*** 
      * 取得公钥 
      * @param keyMap 
      * @return 
      * @throws Exception 
      */  
     public static String getPublicKey(Map keyMap) throws Exception {  
         Key key = (Key) keyMap.get(public_key);  
         return encryptBASE64(key.getEncoded());  
     }  
  
  
  
       
    /** 
     * BASE64解密 
     *  
     * @param key 
     * @return 
     * @throws Exception 
     */  
    public static byte[] decryptBASE64(String key) throws Exception {  
        return (new BASE64Decoder()).decodeBuffer(key);  
    }  
  
    /** 
     * BASE64 加密 
     *  
     * @param key 
     * @return 
     * @throws Exception 
     */  
    public static String encryptBASE64(byte[] key) throws Exception {  
        return (new BASE64Encoder()).encodeBuffer(key);  
    }  
  
    public static void main(String[] args) throws Exception{  
        String inputStr = "Hello,中国,你好啊！";  
        byte[] data = inputStr.getBytes();  
        // 构建密钥  
        Map<String, Object> keyMap = DSASignaureUtil.initKey();  
        // 获得密钥  
        String publicKey = DSASignaureUtil.getPublicKey(keyMap);  
        String privateKey = DSASignaureUtil.getPrivateKey(keyMap);  
        System.err.println("公钥:\r" + publicKey);  
        System.err.println("私钥:\r" + privateKey);  
        // 产生签名  
        String sign = DSASignaureUtil.sign(data, privateKey);  
        System.err.println("签名:\r" + sign);  
        // 验证签名  
        boolean status = DSASignaureUtil.verify(data, publicKey, sign);  
        System.err.println("状态:\r" + status);  
        if(status){  
            System.out.println("原文:"+new String(data));  
        }  
          
  
    }  
  
      
}  