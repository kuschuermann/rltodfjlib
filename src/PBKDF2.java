package com.ringlord.crypto;

import java.io.UnsupportedEncodingException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>Implements the "PBKDF2WithHmacSHA1" algorithm accoding to
 * RFC&nbsp;2898.</p>
 *
 * <p>Unlike the standard Java crypto library's {@link
 * java.crypto.spec.PBEKeySpec} this implementation allows for
 * byte[]-based passwords and is not limited to UTF-8 encoded
 * char[].</p>
 *
 * <p>This implementation was, in fact, developed specifically to deal
 * with encrypted (password protected) OpenOffice.org documents which
 * do not merely provide a password to the PBKDF2 algorithm, but an
 * SHA1-hash thereof, necessitating an implementation of PBKDF2 that
 * accepts arbitrary binary data.</p>
 *
 * <p>I would like to offer my thanks to the following people for
 * their various input, all of which in combination not merely
 * encouraged me to continue seeking for a solution to this problem
 * but led me on a path of discovery about cryptography that resulted
 * ultimately in the following details about OpenOffice.org use of
 * passwords and cryptography:</p>
 *
 * <ol>
 * <li>Steven Elliot, whose lucid description as well as scripts and
 *     software to decrypt OOo documents explained two crucial pieces
 *     that had eluded me before: The use of SHA1 on the password
 *     (which explained why the standard Java library didn't work),
 *     and the fact that the header/footer on the compressed data need
 *     to be reconstructed.
 * <li>Matthias G&auml;rtner, whose PBKDF2 package forms the basis for
 *     our code,
 * <li><i>sabre150</i>, prolific, and unforgivingly sarcastic expert
 *     from the Sun Forums who offers hints and advise but refuses to
 *     provide solutions for those who don't even understand what they
 *     are doing: in cryptography, muddling about leads to poor (and
 *     therefore terribly bad, even dangerous) "solutions".
 * </ol>
 *
 * <p>Now, OpenOffice.org protects documents using passwords as
 * follows:</p>
 *
 * <ol>
 * <li>User-entered passwords are run through SHA1 to produce a 160
 * bit (20 byte) value; The (binary) password is then turned via
 * PBKDF2 algorithm into a secret key: As Steven Elliot remarks, it
 * the first step is rather redundant as PBKDF2 performs SHA1 on the
 * password 1024 times (in the case of OpenOffice.org's use of
 * PBKDF2) but that's what we have to work with;
 * <li>The (XML) document is compressed (see RFC&nbsp;1950,
 * RFC&nbsp;1951, and RFC&nbsp;1952), the 10-byte header (magic
 * number, version number, and timestampe) as well as the 8-byte
 * footer (CRC-32 checksum and original file's size) are stripped
 * away; the resulting body is then encrypted using the
 * "Blowfish/CFB/NoPadding" cipher, combined with a randomly generated
 * initialization vector.
 * <li>The CRC-32, salt, initialization vector, iteration count
 * (1024), and cipher (Blowfish/CFB), are all described in the
 * document's meta-data (the manifest).
 * </ol>
 *
 * @see <a href="http://rtner.de/software/PBKDF2.html">rtner.de/software/PBKDF2.html</a>
 **/
public class PBKDF2
{
  public static byte[] deriveKey( final byte[] password,
                                  final byte[] salt,
                                  final int iterationCount,
                                  final int dkLen )
    throws NoSuchAlgorithmException,
           InvalidKeyException
  {
    final SecretKeySpec keyspec = new SecretKeySpec( password, "HmacSHA1" );
    final Mac prf = Mac.getInstance( "HmacSHA1" );
    prf.init( keyspec );
    
    // Note: hLen, dkLen, l, r, T, F, etc. are horrible names for
    //       variables and functions in this day and age, but they
    //       reflect the terse symbols used in RFC 2898 to describe
    //       the PBKDF2 algorithm:

    final int hLen = prf.getMacLength();	// this will be 20 for SHA1
    final int l = ceil( dkLen, hLen);		// this will be 1 for 128bit (16-byte) keys
    final int r = dkLen - (l-1)*hLen;		// this will be 16 for 128bit (16-byte) keys

    final byte T[] = new byte[l * hLen];
    int ti_offset = 0;
    for (int i = 1; i <= l; i++)
      {
        F( T, ti_offset, prf, salt, iterationCount, i );
        ti_offset += hLen;
      }
    if (r < hLen)
      {
        // Incomplete last block
        byte DK[] = new byte[dkLen];
        System.arraycopy(T, 0, DK, 0, dkLen);
        return DK;
      }
    return T;
  }

  /**
   * Integer division with ceiling function.
   * 
   * @param a Divisor
   *
   * @param b Denominator
   *
   * @return ceil(a/b)
   *
   * @see <a href="http://tools.ietf.org/html/rfc2898">RFC 2898 5.2 Step 2.</a>
   **/
  public static int ceil( final int a,
                          final int b )
  {
    int m = 0;
    if( (a % b) > 0 )
      {
        m = 1;
      }
    return a / b + m;
  }


  private static void F( final byte[] dest,
                         final int offset,
                         final Mac prf,
                         final byte[] S,
                         final int c,
                         final int blockIndex )
  {
    final int hLen = prf.getMacLength();
    byte U_r[] = new byte[ hLen ];
    
    // U0 = S || INT (i);
    byte U_i[] = new byte[S.length + 4];
    System.arraycopy( S, 0, U_i, 0, S.length );
    INT( U_i, S.length, blockIndex );
    
    for( int i = 0; i < c; i++ )
      {
        U_i = prf.doFinal( U_i );
        xor( U_r, U_i );
      }
    System.arraycopy( U_r, 0, dest, offset, hLen );
  }

    /**
     * Block-Xor. Xor source bytes into destination byte buffer. Destination
     * buffer must be same length or less than source buffer.
     * 
     * @param dest
     * @param src
     */
  private static void xor( final byte[] dest,
                           final byte[] src )
  {
    for( int i = 0; i < dest.length; i++ )
      {
        dest[i] ^= src[i];
      }
  }

  /**
   * Four-octet encoding of the integer i, most significant octet first.
   * 
   * @see <a href="http://tools.ietf.org/html/rfc2898">RFC 2898 5.2 Step 3.</a>
   * @param dest
   * @param offset
   * @param i
   */
  private static void INT( final byte[] dest,
                           final int offset,
                           final int i )
  {
    dest[offset + 0] = (byte) (i / (256 * 256 * 256));
    dest[offset + 1] = (byte) (i / (256 * 256));
    dest[offset + 2] = (byte) (i / (256));
    dest[offset + 3] = (byte) (i);
  }
}
