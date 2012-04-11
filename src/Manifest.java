package com.ringlord.odf;

import java.io.InputStream;
import java.io.IOException;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.Enumeration;

import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;

import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.InputSource;
import org.xml.sax.Attributes;
import org.xml.sax.SAXParseException;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.ringlord.mime.Base64;

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
 * <p>Supports parsing and maintains a mapping of the resulting named
 * {@linkplain Entry entries} comprising the {@link Container}.</p>
 *
 * @author K. Udo Schuermann
 **/
class Manifest
  extends DefaultHandler
  implements Iterable<Entry>
{
  Manifest( final InputStream f,
            final ZipFile container )
    throws ParserConfigurationException,
           SAXException,
           IOException
  {
    synchronized( Manifest.class )
      {
        if( pf == null )
          {
            pf = SAXParserFactory.newInstance();
            pf.setNamespaceAware( false ); // we want to see the names with ':' in them
            pf.setValidating( false );
            pf.setFeature("http://xml.org/sax/features/validation",false);
            pf.setFeature("http://apache.org/xml/features/validation/schema",false);
            pf.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar",false);
            pf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd",false);
          }
      }

    this.container = container;
    final SAXParser p = pf.newSAXParser();
    final InputSource s = new InputSource( f );

    p.parse( s, this );

    final Enumeration<? extends ZipEntry> allEntries = container.entries();
    while( allEntries.hasMoreElements() )
      {
        final ZipEntry ze = allEntries.nextElement();
        final String name = ze.getName();
        final Entry e = entries.get( name );
        if( e == null )
          {
            entries.put( name, new Entry(name,null,container) );
          }
      }
  }

  public Entry get( final String name )
  {
    return entries.get( name );
  }

  public void add( final Entry entry )
  {
    entries.put( entry.name(), entry );
  }

  public boolean remove( final Entry entry )
  {
    return (entries.remove(entry.name()) != null);
  }

  public Iterator<Entry> iterator()
  {
    final List<Entry> entries = new ArrayList<Entry>();
    entries.addAll( this.entries.values() );
    return entries.iterator();
  }

  public void characters( final char[] data,
                          final int start,
                          final int length )
  {
  }

  public void startElement( final String uri,
                            final String localName,
                            final String qName,
                            final Attributes attribs )
  {
    final Map<String,String> attributes = new LinkedHashMap<String,String>();
    final int attrCount = attribs.getLength();
    for( int i=0; i<attrCount; i++ )
      {
        attributes.put( attribs.getQName(i),
                        attribs.getValue(i) );
      }

    if( ! isODF )
      {
        if( qName.equals("manifest:manifest") )
          {
            final String manifestType = attributes.get( "xmlns:manifest" );
            if( "http://openoffice.org/2001/manifest".equals(manifestType) ||
                "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0".equals(manifestType) )
              {
                isODF = true;
              }
            else
              {
                throw new IllegalArgumentException( "Unrecognized manifest type (neither "+
                                                    "OpenOffice.org v1 nor a recognized "+
                                                    "OASIS Open Document Format: "+
                                                    manifestType );
              }
          }
        else
          {
            throw new IllegalArgumentException( "Unrecognized META-INF/manifest.xml: "+
                                                "Expected 'manifest:manifest' as top "+
                                                "level element, rather than '"+
                                                qName+"'" );
          }
      }
    else
      {
        // We get here only if we actually have a recognized OOo or
        // ODF manifest

        if( qName.equals("manifest:file-entry") )
          {
            info = new LinkedHashMap<String,Map<String,String>>();
          }

        info.put( qName, attributes );
      }
  }

  public void endElement( final String uri,
                          final String localName,
                          final String qName )
  {
    if( qName.equals("manifest:file-entry") )
      {
        /*
          manifest:file-entry
                manifest:media-type             text/xml
                manifest:full-path              meta.xml
                manifest:size                   2003
            manifest:encryption-data
                manifest:checksum-type          urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k
                manifest:checksum               (base64-encoded binary)
              manifest:algorithm
                manifest:algorithm-name         http://www.w3.org/2001/04/xmlenc#aes256-cbc
                manifest:initialization-vector  (base64-encoded binary)
              manifest:key-derivation
                manifest:key-derivation-name    PBKDF2
                manifest:key-size               32
                manifest:iteration-count        1024
                manifest:salt                   (base64-encoded binary)
              manifest:start-key-generation
                manifest:start-key-generation-name      http://www.w3.org/2000/09/xmldsig#sha256
                manifest:key-size               32
        */

        final Crypto crypto;
        final Map<String,String> cAttr = info.get( "manifest:encryption-data" );
        if( cAttr == null )
          {
            crypto = null;
          }
        else
          {
            final Map<String,String> kAttr = info.get( "manifest:key-derivation" );
            final Map<String,String> aAttr = info.get( "manifest:algorithm" );
            final Map<String,String> pAttr = info.get( "manifest:start-key-generation" );

            try
              {
                crypto = new Crypto( cAttr, kAttr, aAttr, pAttr );
              }
            catch( NoSuchAlgorithmException | NoSuchPaddingException x )
              {
                final IllegalStateException boom =
                  new IllegalStateException( "Unsupported crypto" );
                boom.initCause( x );
                throw boom;
              }
          }

        final Map<String,String> fAttr = info.get( "manifest:file-entry" );
        final String name = fAttr.get("manifest:full-path");
        entries.put( name, new Entry(name,
                                     crypto,
                                     container) );
      }
    else if( qName.equals("manifest:manifest") )
      {
        entries.put( "META-INF/manifest.xml",
                     new Entry("META-INF/manifest.xml",
                               null,
                               container) );
      }
  }

  public String toString()
  {
    return entries.toString();
  }

  private ZipFile container;
  private boolean isODF;
  //
  private Map<String,Map<String,String>> info;
  //
  private Map<String,Entry> entries = new LinkedHashMap<String,Entry>();
  private static SAXParserFactory pf;
}
