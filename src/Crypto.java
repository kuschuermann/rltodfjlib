package com.ringlord.crypto;

import java.io.CharArrayWriter;
import java.io.UnsupportedEncodingException;

import java.security.MessageDigest;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Map;

import com.ringlord.mime.Base64;

/**
 * <p>Encrypt/decrypt data using a password. Although this class is
 * intended to be flexible, it is presently limited to use the PBKDF2
 * password-based key derivative function for key strengthening and
 * is not prepared to adjust to other algorithms.</p>
 *
 * <p>This limitation is entirely due to the fact that the Java crypto
 * libraries require a password-based keys to be built from UTF-8
 * encoded passwords rather than binary and we had to supply a
 * binary-capable implementation of our own; although it could be
 * ascribed to laziness, we lack the requisite knowledge to integrate
 * this class into the Java crypto framework.</p>
 *
 * @author K. Udo Schuermann
 **/
public class Crypto
{
  // ======================================================================
  // Constructors
  // ======================================================================

  public Crypto( final Map<String,String> encryptionData,
                 final Map<String,String> keyDerivationData,
                 final Map<String,String> algorithmData,
                 final Map<String,String> startKeyGenerationData )
    throws NoSuchAlgorithmException,
           NoSuchPaddingException
  {
    super();

    /*
    System.err.println( "--------------------------------------------------" );
    System.err.println( "e="+encryptionData );
    System.err.println( "a="+algorithmData );
    System.err.println( "k="+keyDerivationData );
    System.err.println( "p="+startKeyGenerationData );
    System.err.println( "--------------------------------------------------" );
    */

    this.checksumType  = encryptionData.get( "manifest:checksum-type" );
    this.checksum      = toByteArray( encryptionData.get("manifest:checksum") );

    this.algorithmName = algorithmData.get( "manifest:algorithm-name" );
    this.initVector    = toByteArray( algorithmData.get("manifest:initialisation-vector") );


    this.keyDerivName  = keyDerivationData.get( "manifest:key-derivation-name" );
    if( keyDerivationData.get("manifest:key-size") == null )
      {
        this.keyDerivSize  = 16;
      }
    else
      {
        this.keyDerivSize  = toInt( keyDerivationData.get("manifest:key-size") );
      }
    this.keyDerivIter  = toInt( keyDerivationData.get("manifest:iteration-count") );
    this.salt          = toByteArray( keyDerivationData.get("manifest:salt") );

    if( startKeyGenerationData == null )
      {
        this.startKeyGen   = "SHA1";
        this.startKeySize  = 16;
      }
    else
      {
        this.startKeyGen   = startKeyGenerationData.get( "manifest:start-key-generation-name" );
        this.startKeySize  = toInt( startKeyGenerationData.get("manifest:key-size") );
      }

    init();
  }

  public Crypto( final String checksumType,
                 final byte[] checksum,
                 final String algorithmName,
                 final byte[] initVector,
                 final String keyDerivationAlgorithmName,
                 final int keyDerivationSize,
                 final int keyDerivationIterationCount,
                 final byte[] salt,
                 final String startKeyGenerationName,
                 final int startKeySize )
    throws NoSuchAlgorithmException,
           NoSuchPaddingException
  {
    super();

    this.checksumType  = checksumType;
    this.checksum      = checksum;

    this.algorithmName = algorithmName;
    this.initVector    = initVector;

    this.keyDerivName  = keyDerivationAlgorithmName;
    this.keyDerivSize  = keyDerivationSize;
    this.keyDerivIter  = keyDerivationIterationCount;
    this.salt          = salt;

    this.startKeyGen   = startKeyGenerationName;
    this.startKeySize  = startKeySize;

    init();
  }

  private void init()
    throws NoSuchAlgorithmException,
           NoSuchPaddingException
  {
    // ----------------------------------------------------------------------
    // Translate the cipher algorithm from the version used by the ODF
    // container to the one recognized by the Java crypto libraries:
    String algorithmID;
    if( algorithmName.equals("Blowfish CFB") )
      {
        algorithmID = "Blowfish/CFB/NoPadding";
      }
    else if( algorithmName.equals("http://www.w3.org/2001/04/xmlenc#aes256-cbc") )
      {
        algorithmID = "AES/CBC/NoPadding";
      }
    else // not recognized, unsupported, most likely won't work
      {
        algorithmID = algorithmName;
      }
    this.cipher = Cipher.getInstance( algorithmID );

    // ----------------------------------------------------------------------
    // Translate the public key derivation algorithm from the version
    // used by the ODF container to version recognized by the Java
    // crypto libraries:
    String keyDerivationID;
    if( keyDerivName.equals("PBKDF2") )
      {
        keyDerivationID = "PBKDF2WithHmacSHA1";
      }
    else // not recognized, unsupported, most likely won't work
      {
        keyDerivationID = keyDerivName;
      }
    this.keyFactory = SecretKeyFactory.getInstance( keyDerivationID );

    // ----------------------------------------------------------------------
    // A cipher specification is either "Name" or "Name/Mode/Padding",
    // so we'll look for the first '/' symbol and, if present, take
    // the name that precedes it or the whole thing if there is no '/'
    // for the name of the secret key algorithm:
    final int slashPos = algorithmID.indexOf("/");
    this.keyAlgorithm = (slashPos < 0
                         ? algorithmID
                         : algorithmID.substring(0,slashPos));

    System.err.println( "---------------------------------------------" );
    System.err.println( "ChecksumType   = "+checksumType );
    System.err.println( "Checksum.len   = "+checksum.length );
    System.err.println( "KeyAlgorithm   = "+algorithmName );
    System.err.println( "KeyAlgorithmID = "+algorithmID+"  ==>  "+keyAlgorithm );
    System.err.println( "InitVector.len = "+initVector.length );
    System.err.println( "KeyDerivation  = "+keyDerivName );
    System.err.println( "KeyDerivationID= "+keyDerivationID );
    System.err.println( "KeyDerivSize   = "+keyDerivSize );
    System.err.println( "KeyDerivIter   = "+keyDerivIter );
    System.err.println( "Salt.len       = "+salt.length );
    System.err.println( "StartKeyGen    = "+startKeyGen );
    System.err.println( "StartKeySize   = "+startKeySize );
  }

  /**
   * Encrypts the given plain text using a key based on password
   * parameters and an initializaton vector.
   *
   * @see #encrypt(byte[],Key,byte[])
   **/
  public byte[] encrypt( final byte[] plainText,
                         final String password )
    throws InvalidKeyException,
           InvalidKeySpecException,
           InvalidAlgorithmParameterException,
           IllegalBlockSizeException,
           BadPaddingException,
           NoSuchAlgorithmException,
           UnsupportedEncodingException
  {
    final Key key = buildKey( password );
    return encrypt( plainText, key );
  }

  /**
   * Encrypts the given plain text using a key and initialization
   * vector.
   **/
  public byte[] encrypt( final byte[] plainText,
                         final Key key )
    throws InvalidKeyException,
           InvalidAlgorithmParameterException,
           IllegalBlockSizeException,
           BadPaddingException
  {
    final IvParameterSpec iv = new IvParameterSpec( initVector );
    cipher.init( Cipher.ENCRYPT_MODE, key, iv );
    return cipher.doFinal( plainText );
  }

  /**
   * Decrypts the given cipher text using a key based on password
   * parameters and an initialization vector.
   *
   * @see #decrypt(byte[],Key,byte[])
   **/
  public byte[] decrypt( final byte[] cipherText,
                         final String password )
    throws InvalidKeyException,
           InvalidKeySpecException,
           InvalidAlgorithmParameterException,
           IllegalBlockSizeException,
           BadPaddingException,
           NoSuchAlgorithmException,
           UnsupportedEncodingException
  {
    final Key key = buildKey( password );
    return decrypt( cipherText, key );
  }

  /**
   * Decrypts the given cipher text using a key and an initialization
   * vector.
   **/
  public byte[] decrypt( final byte[] cipherText,
                         final Key key )
    throws InvalidKeyException,
           InvalidAlgorithmParameterException,
           IllegalBlockSizeException,
           BadPaddingException,
           NoSuchAlgorithmException
  {
    final IvParameterSpec iv = new IvParameterSpec( initVector );
    cipher.init( Cipher.DECRYPT_MODE, key, iv );
    return verify( cipher.doFinal(cipherText) );
  }

  private byte[] verify( final byte[] result )
    throws NoSuchAlgorithmException
  {
    final MessageDigest digest;
    if( "SHA1/1K".equals(checksumType) )
      {
        digest = MessageDigest.getInstance( "SHA1" );
        if( result.length < 1024 )
          {
            digest.update( result );
          }
        else
          {
            digest.update( result, 0, 1024 );
          }
      }
    else if( "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k".equals(checksumType) )
      {
        digest = MessageDigest.getInstance( "SHA-256" );
        if( result.length < 1024 )
          {
            digest.update( result );
          }
        else
          {
            digest.update( result, 0, 1024 );
          }
      }
    else
      {
        // no checksum available, cannot verify, assume that it's fine
        return result;
      }

    final byte[] test = digest.digest();
    for( int i=0; i<checksum.length; i++ )
      {
        if( test[i] != checksum[i] )
          {
            throw new IllegalArgumentException( "Checksum mismatch (wrong key/password?)" );
          }
      }

    return result;
  }

  /**
   * Builds a password-based key (PBK) that is compatible with the
   * chosen cipher algorithm using the {@link KeyFactory} indicated in
   * the constructor. Note that this will only work if you have chosen
   * a PBK-style algorith such as "PBKDF2WithHmacSHA1" or similar.
   **/
  public Key buildKey( final String password )
    throws InvalidKeyException,
           InvalidKeySpecException,
           NoSuchAlgorithmException,
           UnsupportedEncodingException
  {
    final byte[] sha;
    if( "http://www.w3.org/2000/09/xmldsig#sha256".equals(startKeyGen) )
      {
        sha = toSHA256( password );
      }
    else
      {
        sha = toSHA1( password );
      }
    final byte[] derivedKey = PBKDF2.deriveKey( sha,
                                                salt,
                                                keyDerivIter,
                                                keyDerivSize );
    return new SecretKeySpec( derivedKey,
                              keyAlgorithm );
  }

  private static byte[] toByteArray( final String base64Data )
  {
    return Base64.decode( base64Data.getBytes() );
  }
  private static int toInt( final String text )
  {
    return Integer.valueOf( text );
  }
  private static byte[] toSHA256( final String password )
    throws NoSuchAlgorithmException,
           UnsupportedEncodingException
  {
    final byte[] passwordCharacters = password.getBytes( "UTF-8" );

    final MessageDigest sha256Digester = MessageDigest.getInstance( "SHA-256" );
    return sha256Digester.digest( passwordCharacters );
  }
  private static byte[] toSHA1( final String password )
    throws NoSuchAlgorithmException,
           UnsupportedEncodingException
  {
    final byte[] passwordCharacters = password.getBytes( "UTF-8" );

    final MessageDigest sha1Digester = MessageDigest.getInstance( "SHA1" );
    return sha1Digester.digest( passwordCharacters );
  }

  // ======================================================================
  // Fields and Constants
  // ======================================================================

  private Cipher cipher;
  private SecretKeyFactory keyFactory;
  private String keyAlgorithm; // based on cipherType
  //
  private final String checksumType;
  private final byte[] checksum;
  private final String algorithmName;
  private final byte[] initVector;
  private final String keyDerivName;
  private final int keyDerivSize;
  private final int keyDerivIter;
  private final byte[] salt;
  private final String startKeyGen;
  private final int startKeySize;
}
