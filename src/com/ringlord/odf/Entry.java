package com.ringlord.odf;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.nio.charset.Charset;

import java.util.Map;
import java.util.HashMap;

import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;

import java.util.zip.InflaterInputStream;
import java.util.zip.Inflater;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import com.ringlord.crypto.Crypto;

// ======================================================================
// This file is part of the Ringlord Technologies Java ODF Library,
// which provides access to the contents of OASIS ODF containers,
// including encrypted contents.
//
// Copyright (C) 2012 K. Udo Schuermann
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
// ======================================================================

/**
 * <p>A single (file) component of an OASIS Open Document Format (ODF)
 * container. The Entry is intended to be immutable. It carries with
 * it cryptographic information.</p>
 *
 * <p>The simplest means to obtain the data for an Entry is to call
 * {@link #data()} for an an {@link #isEncrypted()} Entry, and {@link
 * #data(String)} for an encrypted one. For encrypted data this is a
 * wrapper for the following processing steps:</p>
 *
 * <pre>
 *   // Obain the raw (encrypted) data for this entry (this comes
 *   // straight from the zip file); if you know that the Entry is not
     // encrypted then this is all you really need to do:
 *   byte[] raw = entry.raw();
 *
 *   // Obtain this Entry's cryptographical information. This was
 *   // extracted from the META-INF/manifest.xml file; if the Entry
 *   // was not encrypted then this method call returns null
 *   Crypto crypto = entry.getCrypto();
 *
 *   // Generate a cryptographical key based on a password. The
 *   // Crypto info specifies how this password is to be converted
 *   // (strengthened) into something resembling a decent Key
 *   // (i.e. use PBKDF2 with 1024 iterations):
 *   javax.crypto.Key key = crypto.makeKey( password );
 *
 *   // decrypt this data using the info given by the cryptographical
 *   // information, and the key we have built (based on a password).
 *   // We'll ask this method NOT to verify the data ('false') as we
 *   // are demonstrating each individual step here...
 *   byte[] decrypted = crypto.decrypt( raw, key, false );
 *
 *   // And NOW will verify the data; this throws an exception if
 *   // the verification fails:
 *   byte[] verifiedOriginal = entry.verify( decrypted );
 *
 *   // And now inflate (uncompress) the data; if this throws an
 *   // IOException that the data was not deflated/compressed and
 *   // 'verifiedOriginal' is the original data.
 *   byte[] uncompressedOriginal = entry.inflate( verifiedOriginal );
 * </pre>
 *
 * @author K Udo Schuermann
 **/
public class Entry
{
  /**
   * Ignores bad checksums on two specific files ("manifest.rdf" and
   * "Configuration2/accelerator/current.xml") resulting from what
   * appears to be a bug(?) in LibreOffice 3.5.x where the checksum of
   * the decrypted data on the two files fails, even though the data
   * (once inflated) is perfectly fine.
   *
   * Whether or not this is a bug in LibreOffice or a brainfart on my
   * part is under investigation.
   **/
  public static final boolean SPECIAL_IGNORE_BAD_CHECKSUMS = true;

  /**
   * Create a new Entry.
   *
   * @param name The name of the Entry. Within any single {@link
   * Container} this name must be unique. It must be the same by which
   * the item is recorded in the associated {@link ZipFile}.
   *
   * @param crypto Optional cryptographical information about the
   * Entry. If the Entry is encrypted this must be non-null; an
   * unencrypted entry must indicate that with a null here.
   *
   * @param container A reference to the {@link ZipFile} from which
   * the Entry's actual data will be extracted. This must not be null.
   **/
  public Entry( final String name,
                final Crypto crypto,
                final ZipFile container )
  {
    super();
    this.name = name;
    this.crypto = crypto;
    this.container = container;
  }

  /**
   * The (unique and case-sensitive) name of this entry. It cannot be
   * modified.
   **/
  public String name()
  {
    return name;
  }

  /**
   * <p>The data associated with an <em>{@link #isEncrypted()
   * unencrypted} Entry}.</p>
   *
   * @return The Entry's data, or null if the entry's data could not
   * be retrieved (example: Directories have no associated data)
   *
   * @see #data(String)
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
    // If we have cryptographical info then we called the wrong method!
    if( crypto != null )
      {
        throw new IllegalArgumentException( "Cannot decrypt without key/password" );
      }

    final byte[] raw = raw();
    if( raw == null )
      {
        return null;
      }

    try
      {
        return inflate( raw );
      }
    catch( Exception x )
      {
        return raw;
      }
  }

  /**
   * <p>The data associated with an {@link Entry}; whether the entry
   * is expected to be encrypted or unencrypted is determined by the
   * parameter.</p>
   *
   * @param password 'null' if the entry is to be treated as
   * unencrypted data (in which case you should really call {@link
   * #data()}, instead); non-null for the password to be used to
   * decrypt encrypted data.
   *
   * @return The entry's data (decrypted if the correct password was
   * supplied) or null if the associated data could not be retrieved
   * (example: Directories have no associated data).
   *
   * @throws IllegalArgumentException The password has not decrypted
   *         the data successfully (wrong password); or a password was
   *         given when the (unencrypted) entry does not need one.
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
    if( password == null )
      {
        return data();
      }

    if( crypto == null )
      {
        throw new IllegalArgumentException( "Unencrypted entry does "+
                                            "not require a password" );
      }

    final byte[] raw = raw();
    byte[] plain;
    try
      {
        plain = crypto.decrypt( raw, password, true );
      }
    catch( IllegalArgumentException x )
      {
        if( SPECIAL_IGNORE_BAD_CHECKSUMS &&
            ("manifest.rdf".equals(name) ||
             "Configurations2/accelerator/current.xml".equals(name)) &&
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc".equals(crypto.getAlgorithmName()) &&
            "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k".equals(crypto.getChecksumType()) )
          {
            plain = crypto.decrypt( raw, password, false );
            final byte[] inflated = inflate( plain );
            System.err.println( "WARNING: Ignoring (as configured) failed checksum for "+
                                "\""+name+"\" ("+raw.length+" deflated/compressed bytes) "+
                                "that inflate to the following "+inflated.length+" bytes:" );
            System.err.println( "-----( START "+name+" )------------------------------" );
            System.err.println( new String(inflated,UTF8) );
            System.err.println( "-----( END "+name+" )--------------------------------" );
            return inflated;
          }
        else
          {
            throw x;
          }
      }
    try
      {
        return inflate( plain );
      }
    catch( IOException x )
      {
        return plain;
      }
  }

  /**
   * <p>The data associated with an {@link Entry}; whether the entry
   * is expected to be encrypted or unencrypted is determined by the
   * parameter.</p>
   *
   * @param key 'null' if the entry is to be treated as unencrypted
   * data; non-null for the cryptographic key to be used to decrypt
   * encrypted data.
   *
   * @return The entry's data (decrypted if the correct password was
   * supplied).
   *
   * @throws IllegalArgumentException The given key has not decrypted
   *         the data successfully (wrong password); or a Key was
   *         given when the (unencrypted) entry does not need one.
   **/
  public byte[] data( final Key key )
    throws IOException,
           InvalidKeyException,
           InvalidAlgorithmParameterException,
           IllegalBlockSizeException,
           BadPaddingException,
           InvalidKeySpecException,
           NoSuchAlgorithmException
  {
    if( key == null )
      {
        return data();
      }

    if( crypto == null )
      {
        throw new IllegalArgumentException( "Unencrypted entry does "+
                                            "not require a key" );
      }

    final byte[] plain = crypto.decrypt( raw(), key, true );
    try
      {
        return inflate( plain );
      }
    catch( IOException x )
      {
        return plain;
      }
  }

  /**
   * <p>Obtains the raw and compressed data from the Entry completely
   * ignoring the possibility that it may be encrypted. Generally you
   * will want to call {@link #data()} or {@link #data(String)} to
   * access the data in its intended (plain text) form.</p>
   *
   * @return The raw data from the entry, still encrypted if it is an
   * encrypted entry, and still deflated if it was compressed.
   **/
  public byte[] raw()
    throws IOException
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

    return out.toByteArray();
  }

  /**
   * Attempts to inflate deflated (compressed) data.
   **/
  public static byte[] inflate( final byte[] data )
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
   * Determine whether the data is encrypted. The determination is
   * based on the null/non-null status of the 'crypto' parameter given
   * to the constructor.
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

  /**
   * A simplistic text representation of this Entry consisting
   * primarily of the name and a flag that indicates whether it is
   * encrypted.
   **/
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
  private final ZipFile container;
  //
  private static final Charset UTF8 = Charset.forName("UTF-8");
}
