package Tarea2;


import Tarea2.Tarea2;
import Tarea2.Lectura;

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
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

class Lectura extends Thread
{
    public DataInputStream reader;
    String nombre;
    PrivateKey key;
    
    Lectura(DataInputStream in, String nombre, PrivateKey key )
    {
        this.key = key;
        reader = in;
        this.nombre = nombre;
    }
    //desencripta y retorna un arreglo de bytes
    public static byte[] desencriptar(PrivateKey llave, byte[] src)
    {
        byte[] encriptado = null;
        try
        {
            Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
            rsa.init(Cipher.DECRYPT_MODE, llave);   
            encriptado = rsa.doFinal(src);
            
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        }
       
       return encriptado;
    }
    //copy paste del hash de mas abajo
    public static String hash(String src)
    {
        String result = "";
        try
        {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] texto = src.getBytes();
            md.update(texto);
            byte[]digest = md.digest();

            for(byte b : digest)
            {
                result += Integer.toHexString(b & 0xff);
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        }
       
       return result;
    }
    
    @Override
    public void run()
    {
        try 
        {
            // dado que el hilo ya tiene todo lo necesario para leer se definen las variables y se comienza el while true donde leera hasta que acabe la ejecucion del server
            int largo;
            byte[] data = null;
            byte[] firma;
            while(true)
            {
                // se lee el largo del mensaje 
                largo = reader.readInt();
                firma = new byte[largo];
                // ahora se lee la firma 
                reader.readFully(firma, 0, largo);
                
                
                largo = reader.readInt();
                data = new byte[largo];
                // aca se lee el mensaje
                reader.readFully(data, 0, largo);
                // el mensaje se pasa a string dado que no esta encriptado o algo
                String mensaje = new String(data);
                
                //se desencripta el mensaje
                byte[] decrypt = desencriptar(key,firma);
                //se pasa a string
                String des = new String (decrypt);
                // dado que al desencriptar se obtiene un arreglo de 256 bytes muchos de estos estan vacios
                // asi que hay que borran los caracteres vacios sobrantes del mensaje  con trim
                des = des.trim();
                // se obtiene el hash del mensaje sin encriptar
                String hashi = hash(mensaje);
                // se compara el hash con la firma desencriptada
                if(des.compareTo(hashi)==0)
                {
                    // si es igual entonces es seguro y se le agrega los []
                    System.out.println("["+nombre+"]: "+mensaje);
                }
                else
                {
                    // se considera no seguro asi que no se ponen los []
                    System.out.println(nombre+": "+mensaje);
                }
            }
            
        } catch (IOException ex) {
            
            Logger.getLogger(Lectura.class.getName()).log(Level.SEVERE, null, ex);
            System.exit(0);
        }
    }
}
public class Tarea2 {

    private static int PUERTO=1234;
    private static String HOST = "localhost";
    
    public static SSLServerSocket crearServerSocket(int puerto) throws IOException
    {
	SSLServerSocketFactory factory=(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket server = (SSLServerSocket)factory.createServerSocket(PUERTO); 
        return server;
    }
    // crea un string con el hash en md5
    public static String hash(String src)
    {
        String result = "";
        try
        {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] texto = src.getBytes();
            md.update(texto);
            byte[]digest = md.digest();

            for(byte b : digest)
            {
                result += Integer.toHexString(b & 0xff);
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        }
       
       return result;
    }
    
    // encripta y retorna un arreglo de bytes
    public static byte[] encriptar(PublicKey llave, String src)
    {
        byte[] encriptado = null;
        try
        {
            Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
            rsa.init(Cipher.ENCRYPT_MODE, llave);
            encriptado = rsa.doFinal(src.getBytes());
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
        }
       
       return encriptado;
    }
    
    
    public static void main(String args[]) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        //abre la keystore
        File file = new File("llaves.jks");
        InputStream is = new FileInputStream(file);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        String password = "123456";
        keystore.load(is, password.toCharArray());    
        String alias=keystore.aliases().nextElement();
        
        //abre el certificado par abtener las llaves
        Certificate cert = keystore.getCertificate(alias);
	PublicKey publicKey = cert.getPublicKey();
	@SuppressWarnings("unused")
	  PrivateKey privatekey = (PrivateKey) keystore.getKey(alias, "123456".toCharArray()); 
                


        

        Scanner scan = new Scanner(System.in);
        SSLServerSocket server;
        System.out.println("Desea ser el Host? [s/n]");
        char op = scan.nextLine().charAt(0);
        SSLSocket socket=null;
        
        if(op=='s')
        {
            //si va a ser host necesita las llaves del server
            try 
            {
                System.setProperty("javax.net.ssl.keyStore","llavesservidor.jks");
                System.setProperty("javax.net.ssl.keyStorePassword","123456");
                server = crearServerSocket(PUERTO);
                
                System.out.println("Esperando conexion....");
                socket = (SSLSocket) server.accept();
                socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
                
            } catch (IOException ex) {
                Logger.getLogger(Tarea2.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        else
        {
            //en caso de ser cliente necesita el truststore
            System.setProperty("javax.net.ssl.trustStore","truststore_cliente.jks");
	    System.setProperty("javax.net.ssl.trustStorePassword","123456");
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            socket = (SSLSocket) factory.createSocket(HOST,PUERTO);
        }
        
        System.out.println("Conexion aceptada!");
        //se crean los input y output del socket, para la comunicacion
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
        //se crea un hilo para la lectura, de esta forma se permite la llegada de mensajes en cualquier momento
        Lectura l = new Lectura(in,alias, privatekey);
        l.start();
        
        
        
        byte[] data;
        //hilo de escritura
        while(socket.isConnected())
        {
            //se lee el mensaje
            String linea = scan.nextLine();
            // se obtiene el hash md5
            String Hash = hash(linea);
            // se encripta el hash
            data = encriptar(publicKey,Hash);
   
            // para mayor seguridad se envia primero el tamaño de data y luego el mensaje en bytes
            out.writeInt(data.length);
            out.write(data);
            
            data = linea.getBytes();
            out.writeInt(data.length);
            out.write(data);
        }
    }
}
