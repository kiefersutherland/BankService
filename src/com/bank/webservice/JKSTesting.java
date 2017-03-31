package com.bank.webservice;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.security.cert.Certificate;
public class JKSTesting {
	 public static PublicKey getPublicKey(String keyStoreFile,
	   String storeFilePass, String keyAlias) {

	  // ��ȡ��Կ����Ҫ�õ��Ĺ�����
	  KeyStore ks;

	  // ��Կ������Ӧ����
	  PublicKey pubkey = null;
	  try {

	   // �õ�ʵ������
	   ks = KeyStore.getInstance("JKS");
	   FileInputStream fin;
	   try {

	    // ��ȡJKS�ļ�
	    fin = new FileInputStream(keyStoreFile);
	    try {
	     // ��ȡ��Կ
	     ks.load(fin, storeFilePass.toCharArray());
	     java.security.cert.Certificate cert = ks
	       .getCertificate(keyAlias);
	     pubkey = cert.getPublicKey();
	    } catch (NoSuchAlgorithmException e) {
	     e.printStackTrace();
	    } catch (CertificateException e) {
	     e.printStackTrace();
	    } catch (IOException e) {
	     e.printStackTrace();
	    }
	   } catch (FileNotFoundException e) {
	    e.printStackTrace();
	   }
	  } catch (KeyStoreException e) {
	   e.printStackTrace();
	  }
	  return pubkey;
	 }

	 

	 /**
	  * �õ�˽Կ
	  * 
	  * @param keyStoreFile
	  *            ˽Կ�ļ�
	  * @param storeFilePass
	  *            ˽Կ�ļ�������
	  * @param keyAlias
	  *            ����
	  * @param keyAliasPass
	  *            ����
	  * @return
	  */


	 public static PrivateKey getPrivateKey(String keyStoreFile,
	   String storeFilePass, String keyAlias, String keyAliasPass) {
	  KeyStore ks;
	  PrivateKey prikey = null;
	  try {
	   ks = KeyStore.getInstance("JKS");
	   FileInputStream fin;
	   try {
	    fin = new FileInputStream(keyStoreFile);
	    try {
	     try {
	      ks.load(fin, storeFilePass.toCharArray());
	      // �ȴ��ļ�
	      prikey = (PrivateKey) ks.getKey(keyAlias, keyAliasPass
	        .toCharArray());
	      // ͨ������������õ�˽Կ
	     } catch (UnrecoverableKeyException e) {
	      e.printStackTrace();
	     } catch (CertificateException e) {
	      e.printStackTrace();
	     } catch (IOException e) {
	      e.printStackTrace();
	     }
	    } catch (NoSuchAlgorithmException e) {
	     e.printStackTrace();
	    }
	   } catch (FileNotFoundException e) {
	    e.printStackTrace();
	   }
	  } catch (KeyStoreException e) {
	   e.printStackTrace();
	  }
	  return prikey;
	 }

	 public static void main(String[] args) {
	  PublicKey publicKey;
	  PrivateKey privateKey;
	   String keystoreFile = "E:\\tool\\merchant.jks";  
    
       String password = "changeit";  
       String alias = "mykey";  
	  publicKey=getPublicKey(keystoreFile,password,alias);
	  privateKey=getPrivateKey(keystoreFile,password, alias,password);
	  
	  System.out.println(publicKey.toString());
	  System.out.println(privateKey.toString());
	 }
	}