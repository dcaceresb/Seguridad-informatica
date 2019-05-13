package Tarea1;


import java.io.*;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.*;
import javax.net.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

class Lectura extends Thread
{
    public BufferedReader reader;
    String nombre;
    Lectura(BufferedReader br, String nombre)
    {
        reader = br;
        this.nombre = nombre;
    }
    
    @Override
    public void run()
    {
        try 
        {
            while(true)
            {
                String linea = reader.readLine();
                System.out.println(nombre+": "+linea);
            }
            
        } catch (IOException ex) {
            Logger.getLogger(Lectura.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
public class Tarea1 {

    private static int PUERTO=1234;
    private static String HOST = "localhost";
    
    public static SSLServerSocket crearServerSocket(int puerto) throws IOException
    {
	SSLServerSocketFactory factory=(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket server = (SSLServerSocket)factory.createServerSocket(PUERTO); 
        return server;
    }

    public static void main(String args[]) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        File file = new File("llaves.jks");
        InputStream is = new FileInputStream(file);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        String password = "123456";
        keystore.load(is, password.toCharArray());
            
        
        Certificate cert = keystore.getCertificate("david");//el alias
	PublicKey publicKey = cert.getPublicKey();
	@SuppressWarnings("unused")
	  PrivateKey privatekey = (PrivateKey) keystore.getKey("david", "123456".toCharArray()); 
        
        String text = "wena machuao";
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, privatekey);
        byte[] encriptado = rsa.doFinal(text.getBytes());
             System.out.print("texto encriptado::");
      for (byte b : encriptado) {
         System.out.print(Integer.toHexString(0xFF & b));
      }
      System.out.println();

      // Se desencripta
      rsa.init(Cipher.DECRYPT_MODE, publicKey);
      byte[] bytesDesencriptados = rsa.doFinal(encriptado);
      String textoDesencripado = new String(bytesDesencriptados);
        System.out.println("Texto desencriptado:"+textoDesencripado);
        String alias="david";

        System.out.println(publicKey);
        Scanner scan = new Scanner(System.in);
        SSLServerSocket server;
        PrintWriter  escritura;
        BufferedReader lectura;
        System.out.println("Desea ser el Host? [s/n]");
        char op = scan.nextLine().charAt(0);
        SSLSocket socket=null;
        if(op=='s')
        {
            try 
            {
                System.setProperty("javax.net.ssl.keyStore","llavesservidor.jks");
                System.setProperty("javax.net.ssl.keyStorePassword","123456");
                server = crearServerSocket(PUERTO);
                
                System.out.println("Esperando conexion....");
                socket = (SSLSocket) server.accept();
                socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
                System.out.println("Conexion aceptada!");
            } catch (IOException ex) {
                Logger.getLogger(Tarea1.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        else
        {
            System.setProperty("javax.net.ssl.trustStore","truststore_cliente.jks");
	    System.setProperty("javax.net.ssl.trustStorePassword","123456");
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            socket = (SSLSocket) factory.createSocket(HOST,PUERTO);
        }
        escritura = new PrintWriter(socket.getOutputStream(),true);
        lectura = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        
        Lectura l = new Lectura(lectura,alias);
        l.start();
        
        //hilo de escritura
        while(true)
        {
            String linea = scan.nextLine();
            escritura.println(linea);
        }
    }
}
