package com.ringlord.odf;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.util.Map;
import java.util.HashMap;

import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;

import java.util.zip.InflaterInputStream;
import java.util.zip.Inflater;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import com.ringlord.crypto.Crypto;

/**
 * A single file component in an OASIS Open Document File container.
 * The Entry is immutable.
 *
 * @author K Udo Schuermann
 **/
public class Entry
{
  /**
   * Create a new Entry.
   **/
  public Entry( final String name,
                final Crypto crypto,
                final Map<String,Map<String,String>> attribs,
                final ZipFile container )
  {
    super();
    this.name = name;
    this.crypto = crypto;
    this.attribs = attribs;
    this.container = container;
  }

  public Map<String,String> attribs( final String category )
  {
    return attribs.get( category );
  }
  public Map<String,Map<String,String>> attribs()
  {
    return attribs;
  }

  public String name()
  {
    return name;
  }

  /**
   * <strong>Do not modify the contents of the return value!</strong>
   **/
  public byte[] data()
    throws IOException,
           InvalidKeyException,
           InvalidAlgorithmParameterException,
           IllegalBlockSizeException,
           BadPaddingException,
           InvalidKeySpecException,
           NoSuchAlgorithmException
  {
    return data( null );
  }

  /**
   * @throws IllegalArgumentException The password has not decrypted
   *         the data successfully (wrong password)
   **/
  public byte[] data( final String password )
    throws IOException,
           InvalidKeyException,
           InvalidAlgorithmParameterException,
           IllegalBlockSizeException,
           BadPaddingException,
           InvalidKeySpecException,
           NoSuchAlgorithmException
  {
    final ZipEntry e = container.getEntry( name );
    if( e == null )
      {
        return null;
      }

    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final InputStream in = container.getInputStream( e );
    try
      {
        final byte[] buffer = new byte[1024];
        int inBuffer;
        while( (inBuffer = in.read(buffer)) > -1 )
          {
            out.write( buffer, 0, inBuffer );
          }
      }
    finally
      {
        in.close();
      }

    final byte[] raw = out.toByteArray();

    // If we have no crypt then 'raw' is the data we want
    if( crypto == null )
      {
        if( password != null )
          {
            System.err.println( "Unencrypted entry does not require a password!" );
          }

        return inflate(raw);
      }

    // If we have a password to go along with the encryption, then
    // apply it
    if( password != null )
      {
        return inflate( crypto.decrypt(raw,password) );
      }
    throw new IllegalArgumentException( "Cannot decrypt without password" );
  }

  private byte[] inflate( final byte[] data )
    throws IOException
  {
    final ByteArrayInputStream iStream = new ByteArrayInputStream( data );
    final InflaterInputStream inflater = new InflaterInputStream( iStream,
                                                                  new Inflater(true) );
    final ByteArrayOutputStream oStream = new ByteArrayOutputStream();

    final byte[] buffer = new byte[1024];
    int inBuffer;
    while( (inBuffer = inflater.read(buffer)) >= 0 )
      {
        oStream.write( buffer, 0, inBuffer );
      }
    inflater.close();
    oStream.flush();
    oStream.close();

    return oStream.toByteArray();
  }

  /**
   * Determine whether the data is encrypted.
   *
   * @return 'true' if the data is encrypted, and the Entry's contents
   * must be retrieved with {@link #data(String)}, otherwise the data
   * must be retrieved with {@link #data()}.
   **/
  public boolean isEncrypted()
  {
    return (crypto != null);
  }

  /**
   * Retrieve the Entry's cryptographic information.
   *
   * @return The {@link Crypto} object, or null if no cryptographic
   * information was associated with this Entry.
   **/
  public Crypto getCrypto()
  {
    return crypto;
  }

  public String toString()
  {
    final StringBuilder sb = new StringBuilder();
    sb.append( "[name=" ).append( name );
    if( isEncrypted() )
      {
        sb.append( "; encrypted=true" );
      }
    sb.append( "]" );
    return sb.toString();
  }

  private final String name;
  private final Crypto crypto;
  private final Map<String,Map<String,String>> attribs;
  private final ZipFile container;
}
