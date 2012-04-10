package com.ringlord.odf;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;

import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * @author K. Udo Schuermann
 **/
public class Container
  implements Iterable<Entry>
{
  public static void main( final String[] args )
    throws Exception
  {
    for( String name : args )
      {
        final File file = new File(name);
        try
          {
            System.err.print( "Opening "+file );
            final Container odf = new Container(file);
            System.err.println();
            int entryCount = 0;
            for( Entry e : odf )
              {
                System.err.println( "\t"+e );
                ++entryCount;
              }
            System.err.println( "\tTotal: "+entryCount+" entries" );

            final Entry e = odf.get( "content.xml" );
            if( e != null )
              {
                System.err.println( "Found the 'content.xml' entry" );
                final byte[] data = (e.isEncrypted()
                                     ? e.data("test")
                                     : e.data());
                System.err.println( "Got data:\n"+new String(data) );
              }
          }
        catch( IOException x )
          {
            x.printStackTrace();
          }
      }
  }

  public Container( final File file )
    throws IOException,
           ParserConfigurationException,
           SAXException,
           SAXParseException
  {
    super();
    this.file = file;
    if( file.exists() )
      {
        this.container = new ZipFile( file );
        init();
      }
    this.isTemporaryContainer = false;

  }
  /**
   * Processes the InputStream as an ODF container. Due to a bug in
   * the Java library's ZipInputStream (it cannot handle EXT blocks in
   * a non-DEFLATED entry) the given InputStream is persisted to a
   * temporary file, which is then processed as if the ODF container
   * had been given as a {@linkplain #Container(File) local file}. The
   * temporary file is deleted when the {@linkplain #close() container
   * is closed} or the JVM exits in a proper manner.
   *
   * @param f The InputStream to be processed
   *
   * @see #Container(File)
   **/
  public Container( final InputStream f )
    throws IOException,
           ParserConfigurationException,
           SAXException,
           SAXParseException
  {
    super();
    this.file = File.createTempFile( "odf", null);
    this.file.deleteOnExit();

    // Copy the given InputStream into the temporary file
    final OutputStream out = new BufferedOutputStream( new FileOutputStream(this.file) );
    final byte[] buffer = new byte[ 1024 ];
    int inBuffer;
    while( (inBuffer = f.read(buffer)) > -1 )
      {
        out.write( buffer, 0, inBuffer );
      }
    out.flush();
    out.close();

    // Now process the temporary file
    this.container = new ZipFile( this.file );
    this.isTemporaryContainer = true;

    init();
  }

  public File file()
  {
    return file;
  }

  public void save()
  {
    save( this.file );
  }
  public void save( final File file )
  {
    if( file == null )
      {
        throw new IllegalStateException( "Cannot save to a null file" );
      }
  }

  /**
   * Produces an Iterator over the Container's Entries; the Iterator
   * is <em>not backed by the Container</em>, meaning that it is safe
   * to loop over the Iterator and call {@link #remove(Entry)}.
   **/
  public Iterator<Entry> iterator()
  {
    return manifest.iterator();
  }

  public void add( final Entry entry )
  {
    manifest.add( entry );
  }
  public boolean remove( Entry entry )
  {
    return manifest.remove( entry );
  }
  public Entry get( final String name )
  {
    return manifest.get( name );
  }

  public void close()
    throws IOException
  {
    if( file != null )
      {
        try
          {
            container.close();
            if( isTemporaryContainer )
              {
                file.delete();
              }
          }
        finally
          {
            file = null;
          }
      }
  }

  private void init()
    throws IOException,
           ParserConfigurationException,
           SAXException,
           SAXParseException
  {
    final InputStream manifestStream = getInputStream( "META-INF/manifest.xml" );
    if( manifestStream == null )
      {
        throw new IllegalArgumentException( "No META-INF/manifest.xml: Not an ODF container" );
      }

    try
      {
        this.manifest = new Manifest( manifestStream, container );
      }
    finally
      {
        manifestStream.close();
      }
  }

  private Entry getEntry( final String name )
  {
    return manifest.get( name );
  }

  /**
   * <p>Obtain the InputStream representing the data of the indicated
   * file component. The caller is responsible for closing the
   * InputStream.</p>
   **/
  private InputStream getInputStream( final String name )
    throws IOException
  {
    final ZipEntry e = container.getEntry( name );
    if( e == null )
      {
        return null;
      }
    return container.getInputStream( e );
  }

  private Manifest manifest;
  private ZipFile container;
  //
  private File file;
  private final boolean isTemporaryContainer;
}
