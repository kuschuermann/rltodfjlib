package com.ringlord.odf;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;

import org.xml.sax.InputSource;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * <p>Parses the XML to provide only the characters between the XML
 * elements, which is the data most frequently desired for a search
 * unless a "raw search" is intended, in which case this class is not
 * useful.</p>
 *
 * @author K. Udo Schuermann
 **/
public class XMLParser
{
  public String getCharacters( final byte[] data )
    throws IOException
  {
    final ByteArrayInputStream f = new ByteArrayInputStream( data );
    return getCharacters( f );
  }
  public String getCharacters( final InputStream input )
    throws IOException
  {
    try
      {
        final SAXParser parser = getParserFactory().newSAXParser();
        final InputSource inputSource = new InputSource( input );
        final Handler handler = new Handler();
        parser.parse( inputSource, handler );
        return handler.getData();
      }
    catch( SAXException x )
      {
        final IOException up = new IOException( "Failed to parse XML" );
        up.initCause( x ) ;
        throw up;
      }
    catch( ParserConfigurationException x )
      {
        final IOException up = new IOException( "Failed to parse XML" );
        up.initCause( x ) ;
        throw up;
      }
  }

  private class Handler
    extends DefaultHandler
  {
    Handler()
      throws ParserConfigurationException,
             SAXException
    {
      super();
      this.buffer = new StringBuilder();
    }
    void reset()
    {
      buffer.setLength( 0 );
    }
    private String getData()
    {
      return buffer.toString();
    }
    public void startElement( final String namespaceURI,
                              final String localName,
                              final String qName,
                              final Attributes attribs )
    {
    }

    public void endElement( final String namespaceURI,
                            final String localName,
                            final String qName )
    {
    }
    public void characters( final char[] chars,
                            final int start,
                            final int length )
    {
      final String s = new String( chars, start, length ).trim();
      if( s.length() > 0 )
        {
          if( buffer.length() > 0 )
            {
              buffer.append( ' ' );
            }
          buffer.append( s );
        }
    }

    /**
     * Old StarOffice files reference a &lt;!DOCTYPE...&gt; element
     * that forces the XML parser to look for a file named
     * "office.dtd" even though the parser is configured not to
     * validate the document. With this method we'll supply a bogus
     * (empty) DTD which satisfies the parser.
     **/
    public InputSource resolveEntity( final String publicID,
                                      final String systemID )
    {
      final ByteArrayInputStream bais = new ByteArrayInputStream( new byte[]{} );
      return new InputSource( bais );
    }

    private final StringBuilder buffer;
  }
  public synchronized static SAXParserFactory getParserFactory()
  {
    if( factory == null )
      {
        factory = SAXParserFactory.newInstance();
        factory.setNamespaceAware( true );
        factory.setValidating( false );
      }
    return factory;
  }
  private static SAXParserFactory factory;
}
