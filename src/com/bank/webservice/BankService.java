package com.bank.webservice;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

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
     
     //test for new
            
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
	
	
	
	  public static final String CHARSET = "GBK";
	  private static final String fmtTime = "yyyyMMddHHmmss";
    /**
     * 组装报文
     * 这里append比较多，是为了展现报文头的各个字段；实际使用中请按需减少
     * 
     * @param yqdm 20位银企代码
     * @param bsnCode 交易代码
     * @param xmlBody xml主体报文
     * @return
     */
    public static String asemblyPackets(String yqdm, String bsnCode, String xmlBody) {
        
        Date now = Calendar.getInstance().getTime();
        
        StringBuilder buf = new StringBuilder();
        buf.append("A00101");
        
        //编码
        String encoding = "01";
        if (CHARSET.equalsIgnoreCase("GBK")) {
            encoding = "01";
        } else if(CHARSET.equalsIgnoreCase("utf-8") || CHARSET.equalsIgnoreCase("utf8")) {
            encoding = "02";
        }
        buf.append(encoding);//编码
        
        buf.append("01");//通讯协议为TCP/IP
        buf.append(String.format("%20s", yqdm));//银企代码
        try {
            buf.append(String.format("%010d", xmlBody.getBytes(CHARSET).length));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        buf.append(String.format("%-6s", bsnCode));//交易码-左对齐
        buf.append("12345");//操作员代码-用户可自定义
        buf.append("01");//服务类型 01请求
        
        String fmtNow = new SimpleDateFormat(fmtTime).format(now);
        buf.append(fmtNow); //请求日期时间
        
        String requestLogNo = "YQTEST" + fmtNow;
        buf.append(requestLogNo);//请求方系统流水号
        
        buf.append(String.format("%6s", "")); //返回码
        buf.append(String.format("%100s", ""));
        
        buf.append(0); //后续包标志
        buf.append(String.format("%03d", 0));//请求次数
        buf.append("0");//签名标识 0不签
        buf.append("1");//签名数据包格式
        buf.append(String.format("%12s", "")); //签名算法
        buf.append(String.format("%010d", 0)); //签名数据长度
        buf.append(0);//附件数目
        buf.append(xmlBody);//报文体
        
        return buf.toString();
    }
    
	  
}
