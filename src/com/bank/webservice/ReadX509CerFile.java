package com.bank.webservice;

 
import java.io.File;  
import java.io.FileInputStream;  
import java.io.InputStream;  
import java.security.cert.CertificateFactory;  
import java.security.cert.X509Certificate;  
import java.text.SimpleDateFormat;  
import java.util.Date;  

public class ReadX509CerFile {
	 /*** 
     * ��ȡ*.cer��Կ֤���ļ��� ��ȡ��Կ֤����Ϣ 
     * @author xgh 
	 * @throws Exception 
     */  
	
	 public static  void main(String[] args) throws Exception {
		//  System.out.println("ReadX509CerFile");  
  ReadX509CerFile();
	 }
	
    public static  void  ReadX509CerFile()  {  
        try {  
            // ��ȡ֤���ļ�  
  
            File file = new File("E:\\��������ļ�\\�ӿ��ĵ�\\Կ��\\2000739756.cer");  
            InputStream inStream = new FileInputStream(file);  
            // ����X509������  
            CertificateFactory cf = CertificateFactory.getInstance("X.509");  
            //CertificateFactory cf = CertificateFactory.getInstance("X509");  
            // ����֤�����  
            X509Certificate oCert = (X509Certificate) cf  
                    .generateCertificate(inStream);  
            inStream.close();  
            SimpleDateFormat dateformat = new SimpleDateFormat("yyyy/MM/dd");  
            String info = null;  
            // ���֤��汾  
            info = String.valueOf(oCert.getVersion());  
            System.out.println("֤��汾:" + info);  
            // ���֤�����к�  
            info = oCert.getSerialNumber().toString(16);  
            System.out.println("֤�����к�:" + info);  
            // ���֤����Ч��  
            Date beforedate = oCert.getNotBefore();  
            info = dateformat.format(beforedate);  
            System.out.println("֤����Ч����:" + info);  
            Date afterdate = oCert.getNotAfter();  
            info = dateformat.format(afterdate);  
            System.out.println("֤��ʧЧ����:" + info);  
            // ���֤��������Ϣ  
            info = oCert.getSubjectDN().getName();  
            System.out.println("֤��ӵ����:" + info);  
            // ���֤��䷢����Ϣ  
            info = oCert.getIssuerDN().getName();  
            System.out.println("֤��䷢��:" + info);  
            // ���֤��ǩ���㷨����  
            info = oCert.getSigAlgName();  
            System.out.println("֤��ǩ���㷨:" + info);  
  
        } catch (Exception e) {  
            System.out.println("����֤�����");  
            e.printStackTrace();  
        }  
    }  
}
