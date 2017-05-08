package com.bank.webservice;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;

import sun.misc.BASE64Decoder;

public class BankService {
	  public String sayHello (String name){  
	        return name+"说了:hello!";  
	    }  
	//  private   String keystoreFile = "D:/merchant.jks";   
	  private   String keystoreFile = "D:/Service/apache-tomcat-7.0.77/merchant.jks";   
	  private   String password = "changeit";  
	  public   Boolean JavaRsaVerify(String orig,String sign) throws Exception {
	    	
    	  String keyStoreType = "JKS";  
     
     
            
          KeyStore keystore = KeyStore.getInstance(keyStoreType);  
          keystore.load(new FileInputStream(new File(keystoreFile)), password.toCharArray());  
            
          String alias = "sdb";  
      	PublicKey publicKey =  keystore.getCertificate(alias).getPublicKey();
      	
      	String alg="MD5withRSA";
     
  		String encoding = "GBK";
 
  		orig = java.net.URLDecoder.decode(orig, encoding);
  		sign = java.net.URLDecoder.decode(sign, encoding);
  		 
  		
  		orig =  Base64Decode(orig,encoding);
  		sign = Base64Decode(sign,encoding);
 
    	 boolean cc= verifyData(  publicKey,   sign,   orig,   alg) ;
    	return cc;
    	
    }
    
	  public   Boolean JavaRsaVerifyDecode(String orig,String sign) throws Exception {
	    	
    	  String keyStoreType = "JKS";  
       
          KeyStore keystore = KeyStore.getInstance(keyStoreType);  
          keystore.load(new FileInputStream(new File(keystoreFile)), password.toCharArray());  
            
          String alias = "sdb";  
      	PublicKey publicKey =  keystore.getCertificate(alias).getPublicKey();
      	
      	String alg="MD5withRSA";
     
    	 boolean cc= verifyData(  publicKey,   sign,   orig,   alg) ;
    	return cc;
    	
    }
	  
	  
    
	  private static String Base64Decode(String base64, String code) throws Exception {
		byte[] bytes = (byte[]) null;
		try {
			bytes = new BASE64Decoder().decodeBuffer(base64);
		} catch (IOException e) {
			throw new Exception("base64解码出错!");
		}

		String param = "";
		try {
			param = new String(bytes, code);
		} catch (UnsupportedEncodingException e) {
			throw new Exception("base64解码出错!");
		}
		return param;
	}
    
    
    private static boolean verifyData(PublicKey publicKey, String signData, String orgData, String alg) {
		try {
			if ((publicKey == null) || (signData == null) || (orgData == null) || (alg == null)) {
				System.err.println(
						"Error:in KeyStoreUtil.verifyData() . publicKey or signData or orgData or alg is null");
				return false;
			}

			Signature dsa = Signature.getInstance(alg);

			dsa.initVerify(publicKey);

			dsa.update(orgData.getBytes("GBK"));

			byte[] sig = hexToByte(signData);
			return dsa.verify(sig);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	
	private static byte[] hexToByte(String inbuf) {
		int len = inbuf.length() / 2;
		byte[] outbuf = new byte[len];

		for (int i = 0; i < len; ++i) {
			String tmpbuf = inbuf.substring(i * 2, i * 2 + 2);

			outbuf[i] = (byte) Integer.parseInt(tmpbuf, 16);
		}

		return outbuf;
	}
	  
}
