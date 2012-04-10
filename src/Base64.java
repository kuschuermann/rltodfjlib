package com.ringlord.mime;

/**
 * Provides static methods for converting binary (byte[]) data into a
 * BASE-64 encoded byte[] array, and vice versa. Output generated will
 * contain no extraneous whitespace; input to the decoder may contain
 * non-BASE64 vocabulary, which is quietly discarded.<p>
 *
 * The BASE-64 character set contains no symbols that would be
 * problematic in the interpretation of HTML, XML, or even quoted
 * and/or comma-separated data sets, wherefore it is ideal for adding
 * arbitrary binary data to XML documents, email messages, or
 * transmitting such data over streams that are not 8-bit clean. Data
 * encoded in this manner expands its storage requirements by about
 * 35%.
 *
 * This code is based on a less sophisticated version implemented by
 * me in TURBO Pascal around 1987 or 1988 (the early dawn of Ringlord
 * Technologies :-)
 *
 * @author Udo K. Schuermann (walrus@ringlord.com)
 *
 * @version 2.1 (10-Feb-2001)
 **/
final public class Base64
{
  final static public void main( String[] args )
  {
    if( args.length == 0 )
      {
	System.out.println( "Provide a string to encode/decode" );
      }
    else
      {
	System.out.println( "Original = "+args[0] );
	System.out.println( "Encoded  = "+new String( encode( args[0].getBytes() ) ) );
	System.out.println( "Decoded  = "+new String( decode( args[0].getBytes() ) ) );
      }
  }

  /**
   * Transform original (even binary) data into a BASE-64 encoded
   * block of data that can be transmitted over 7-bit lines or
   * embedded in XML without further translation. No extraneous
   * whitespace is generated. I.e. output is not broken up into
   * multiple lines as is common when BASE-64 data is attached to
   * email in the form of MIME attachments.
   *
   * @param original The original bytes to be transformed to standard
   * 7-bit BASE-64.
   *
   * @return The BASE-64 equivalent of the input. No newlines or other
   * formatting data is added.
   **/
  final public static byte[] encode( byte[] original )
  {
    // The number of bytes that we will generated, including
    // possible padding symbols (ending with '=' or '==')
    byte[] result = new byte[ ((original.length+2) / 3) * 4 ];

    // We use only 6 out of 8 bits out of every original byte,
    // therefore expanding our storage requirements to 4 bytes
    // for every given 3.
    for( int iPos=0,oPos=0; iPos<original.length; iPos+=3,oPos+=4 )
      {
	boolean have3=false, have4=false;
	// Now extract up to 3 bytes from the original input
	int data = (original[iPos] & 0xff) << 16;
	if( (iPos+1) < original.length )	// do we have any more?
	  {
	    data |= (original[iPos+1] & 0xff) << 8;
	    have3 = true;
	  }
	if( (iPos+2) < original.length )
	  {
	    data |= original[iPos+2] & 0xff;
	    have4 = true;
	  }

	result[ oPos+3 ] = sixtyFour[ (have4 ? (data & 0x3f) : 64) ];
	data >>= 6;

	result[ oPos+2 ] = sixtyFour[ (have3 ? (data & 0x3f) : 64) ];
	data >>= 6;

	result[ oPos+1 ] = sixtyFour[ (data & 0x3f) ];
	data >>= 6;

	result[ oPos   ] = sixtyFour[ (data & 0x3f) ];
      }
    return result;
  }

  /**
   * Decode a BASE-64 encoded block of bytes to reproduce the original
   * data. As BASE64 data may be reformatted with new lines (but
   * hopefully no other junk) we need to first find out which input
   * characters actually are usable. We actually strip out to ignore
   * all illegal characters, which is less than ideal from a
   * correctness perspective. Given that we trust the caller to give
   * us at least something quite close to BASE64 we'll trust that
   * interspersed characters don't really deviate significantly from a
   * legal encoding. Garbage in, garbage out.
   *
   * @param base64 The BASE-64 input that is to be reconverted to the
   * original data. Any and all illegal symbols in the input are
   * ignored. This is <em>not an open invitation</em> to supply junk
   * to the decoder; the intent is to ignore minor formatting, such as
   * newlines and whitespace, that may have been added for aesthetic
   * purposes.
   *
   * @return The original data from the BASE-64 input.
   **/
  final public static byte[] decode( byte[] base64 )
  {
    int usableBytes = base64.length;
    for( int i=0; i<base64.length; i++ )
      {
	int test = binaryValue[ base64[i] ];
	if( test < 0 )
	  {
	    usableBytes--;
	  }
      }
    int actualLen = ((usableBytes+3) / 4) * 3;
    if( (usableBytes > 1) && (base64[base64.length-2] == '=') )
      {
	actualLen -= 2;
      }
    else if( (usableBytes > 0) && (base64[base64.length-1] == '=') )
      {
	actualLen--;
      }

    byte[] result = new byte[ actualLen ];
    int oPos=0,bucket=0,available=0;
    for( int i=0; i<base64.length; i++ )
      {
	int data = binaryValue[ base64[i] ];
	if( data >= 0 )
	  {
	    bucket = (bucket << 6) | data;
	    if( available >= 2 )	// plus the 6 we just added is at least 8
	      {
		available -= 2;
		result[ oPos++ ] = (byte)((bucket >> available) & 0xff);
	      }
	    else
	      {
		available += 6;	// just added 6 bits
	      }
	  }
      }
    return result;
  }

  /**
   * BASE-64 characters for values 0..63 plus the padding symbol '='
   **/
  static private byte[] sixtyFour = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".getBytes();

  /**
   * Fast lookup table lookup table for converting BASE64 characters
   * to their corresponding value in range 0..63. The padding symbol
   * '=' is NOT part of this; leaving it out will cause that value
   * to be ignored which is exactly what we want
   **/
  static private byte[] binaryValue = new byte[256];
  static
    {
      for( int i=0; i<256; i++ ) binaryValue[i] = -1;
      for( int i='A'; i<='Z'; i++ ) binaryValue[i] = (byte)(     i - 'A');
      for( int i='a'; i<='z'; i++ ) binaryValue[i] = (byte)(26 + i - 'a');
      for( int i='0'; i<='9'; i++ ) binaryValue[i] = (byte)(52 + i - '0');
      binaryValue['+'] = 62;
      binaryValue['/'] = 63;
    }
}
