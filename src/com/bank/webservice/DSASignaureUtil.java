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
 * ǩ����ǩ�㷨:DSA 
 * 1��������Կ�� 
 * 2��ǩ�� 
 * 3����ǩ 
 * @author xgh 
 * 
 */  
public class DSASignaureUtil{  
     public static final String  Algorithm_DSA="DSA";  
     //Ĭ����Կ�ֽ���  
     private static final int key_size=1024;  
     //Ĭ������  
     public static final String default_seed="0f22507a10bbddd07d8a3082122966e3";  
       
     public static final String public_key = "DSAPublicKey";  
     public static final String private_key = "DSAPrivateKey";  
       
     /*** 
      * ������Կ���� 
      * @param seed 
      * @return 
      * @throws Exception 
      */  
     public static Map initKey(String seed) throws Exception{  
         KeyPairGenerator keygen = KeyPairGenerator.getInstance(Algorithm_DSA);  
        //����ʼ�����������  
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
      * ��˽Կ����Ϣ��������ǩ�� 
      * @param data �������� 
      * @param privateKey ˽Կ 
      * @return 
      * @throws Exception 
      */  
     public static String sign(byte[] data,String privateKey)throws Exception{  
        //��������base64�����˽Կ  
        byte[] keyBytes = decryptBASE64(privateKey);  
        //������PKCS8EncodedKeySpec����  
        //PKCS#8:����˽����Կ��Ϣ��ʽ������Ϣ����������Կ�㷨��˽����Կ�Լ���ѡ�����Լ���[27]��  
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
        //��KEY_ALGORITHM��ָ���ļ����㷨  
        KeyFactory keyFactory = KeyFactory.getInstance(Algorithm_DSA);  
        //��ȡ˽Կ�׶���  
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);  
        //��˽Կ����Ϣ��������ǩ��   
        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());  
        signature.initSign(priKey);  
        signature.update(data);  
  
        return encryptBASE64(signature.sign());  
     }  
       
     /*** 
      * У������ǩ�� 
      * @param data �������� 
      * @param publicKey ��Կ 
      * @param sign ����ǩ�� 
      * @return У��ɹ�����true��ʧ�ܷ���false 
      * @throws Exception 
      */  
     public static boolean verify(byte[] data,String publicKey,String sign) throws Exception {  
        // ��������base64����Ĺ�Կ  
        byte[] keyBytes = decryptBASE64(publicKey);  
        // ������X509EncodedKeySpec����  
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
        // ��ALGORITHM��ָ���ļ����㷨  
        KeyFactory keyFactory = KeyFactory.getInstance(Algorithm_DSA);  
        // ��ȡ��Կ�׶���  
        PublicKey pubKey = keyFactory.generatePublic(keySpec);  
        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());  
        signature.initVerify(pubKey);  
        signature.update(data);  
        // ����֤ǩ���Ƿ�����  
        return signature.verify(decryptBASE64(sign));  
     }  
  
      
     /*** 
      * Ĭ��������Կ 
      * @return 
      * @throws Exception 
      */  
     public static Map initKey() throws Exception {  
         return initKey(default_seed);  
     }  
       
      
     /*** 
      * ȡ��˽Կ 
      * @param keyMap 
      * @return 
      * @throws Exception 
      */  
     public static String getPrivateKey(Map keyMap)throws Exception {  
         Key key = (Key) keyMap.get(private_key);  
         return encryptBASE64(key.getEncoded());  
     }  
  
     /*** 
      * ȡ�ù�Կ 
      * @param keyMap 
      * @return 
      * @throws Exception 
      */  
     public static String getPublicKey(Map keyMap) throws Exception {  
         Key key = (Key) keyMap.get(public_key);  
         return encryptBASE64(key.getEncoded());  
     }  
  
  
  
       
    /** 
     * BASE64���� 
     *  
     * @param key 
     * @return 
     * @throws Exception 
     */  
    public static byte[] decryptBASE64(String key) throws Exception {  
        return (new BASE64Decoder()).decodeBuffer(key);  
    }  
  
    /** 
     * BASE64 ���� 
     *  
     * @param key 
     * @return 
     * @throws Exception 
     */  
    public static String encryptBASE64(byte[] key) throws Exception {  
        return (new BASE64Encoder()).encodeBuffer(key);  
    }  
  
    public static void main(String[] args) throws Exception{  
        String inputStr = "Hello,�й�,��ð���";  
        byte[] data = inputStr.getBytes();  
        // ������Կ  
        Map<String, Object> keyMap = DSASignaureUtil.initKey();  
        // �����Կ  
        String publicKey = DSASignaureUtil.getPublicKey(keyMap);  
        String privateKey = DSASignaureUtil.getPrivateKey(keyMap);  
        System.err.println("��Կ:\r" + publicKey);  
        System.err.println("˽Կ:\r" + privateKey);  
        // ����ǩ��  
        String sign = DSASignaureUtil.sign(data, privateKey);  
        System.err.println("ǩ��:\r" + sign);  
        // ��֤ǩ��  
        boolean status = DSASignaureUtil.verify(data, publicKey, sign);  
        System.err.println("״̬:\r" + status);  
        if(status){  
            System.out.println("ԭ��:"+new String(data));  
        }  
          
  
    }  
  
      
}  