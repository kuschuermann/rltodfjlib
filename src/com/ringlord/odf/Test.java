package com.ringlord.odf;

import java.io.File;

import java.util.Set;
import java.util.HashSet;

import com.ringlord.GPL3;

import com.ringlord.odf.Container;
import com.ringlord.odf.Entry;

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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.
// ======================================================================

/**
 * <p>
 * A simple interface to test (and optionally extract) all or some of the files
 * contained in an OASIS Open Document File container. If the file(s) are
 * encrypted, a password is requested (for security reasons a password cannot be
 * given on the command line).
 * </p>
 * 
 * <p>
 * This interface exists primarily for testing and demonstration purposes, as
 * well as a means to print the GPL3 license text, but is not intended to
 * represent a polished tool in its own right.
 * </p>
 * 
 * @author K. Udo Schuermann
 **/
public class Test
{
  public static void main( final String[] args )
    throws Exception
  {
    Operation operation = Operation.LIST;
    Set<Option> options = new HashSet<Option>();
    File containerFile = null;
    Set<String> names = new HashSet<String>();
    boolean acceptFlags = true;
    for( String arg : args )
      {
	if( acceptFlags && arg.startsWith( "-" ) )
	  {
	    if( arg.equals( "-x" ) )
	      {
		operation = Operation.EXTRACT;
		continue;
	      }

	    if( arg.equals( "-L" ) )
	      {
		operation = Operation.LICENSE;
		continue;
	      }

	    if( arg.equals( "-v" ) )
	      {
		options.add( Option.VERBOSE );
		continue;
	      }
	  }
	else
	  {
	    // The first argument is the ODF container filename, all
	    // subsequent arguments are treated as file names within
	    // the container in which we are interested
	    if( containerFile == null )
	      {
		containerFile = new File( arg );
		continue;
	      }
	    else
	      {
		names.add( arg );
	      }
	  }
      }

    if( operation == Operation.LICENSE )
      {
	System.out.println( "Ringlord Technologies ODF Java Library" );
	System.out.println( "Copyright (C) 2012 Ringlord Technologies" );
	System.out.println( "Copyright (C) 2012 K. Udo Schuermann" );
	System.out.println( "All rights reserved" );
	System.out.println();
	System.out.println( GPL3.LICENSE );
	return;
      }

    if( containerFile != null )
      {
	process( operation,
	         options,
	         containerFile,
	         names );
      }
    else
      {
	System.err.println( "Ringlord Technologies ODF Java Library" );
	System.err.println( "Copyright (C) 2012 Ringlord Technologies" );
	System.err.println( "Copyright (C) 2012 K. Udo Schuermann" );
	System.err.println( "All rights reserved" );
	System.err.println();
	System.err.println( "This program comes with ABSOLUTELY NO WARRANTY. This is free" );
	System.err.println( "software, and you are welcome to redistribute it under certain" );
	System.err.println( "conditions. Run it with -L on the command line for details." );
	System.err.println();
	System.err.println( "Command line options:" );
	System.err.println( "  -x   Extract files rather than list them" );
	System.err.println( "  -L   Show software license (GPL3) text" );
	System.err.println( "  -v   Show additional informaton about files" );
	System.err.println();
	System.err.println( "First non-option argument is the name of the ODF container file" );
	System.err.println();
	System.err.println( "Additional names are optional and restrict operation to only" );
	System.err.println( "the named files rather than all files in the container." );
      }
  }


  private static void process( final Operation operation,
	                       final Set<Option> options,
	                       final File containerFile,
	                       final Set<String> args )
    throws Exception
  {
    final Container odf = new Container( containerFile );
    try
      {
	for( Entry e : odf )
	  {
	    if( !args.isEmpty() && !args.contains( e.name() ) )
	      {
		continue; // skip this file
	      }

	    if( e.isEncrypted() )
	      {
		System.err.println( "--------------------------------------------------" );
		if( password == null )
		  {
		    System.out.println( e.getCrypto() + " \t" + e.name() + " (needs password)" );
		    System.err.print( "[7mDocument password[0m: [30;40m" );
		    try
		      {
			// If a Console device is available then use that
			password = new String( System.console().readPassword() );
		      }
		    catch( Exception x )
		      {
			// Otherwise read from stdin (which might have
			// been redirected) in which case our ANSI
			// escape sequences, if they work on the host
			// system at all, will not do pretty things
			// (but that could be fixed by redirecting
			// stderr to eliminate the prompt)
			password = new java.io.BufferedReader( new java.io.InputStreamReader( System.in ) ).readLine();
		      }
		    System.err.print( "[0m[A[K[A[K" );
		  }
		try
		  {
		    final byte[] data = e.data( password );
		    System.out.println( e.getCrypto() + " \t" + e.name() + " DECRYPTED " + data.length + " bytes" );
		    if( options.contains( Option.VERBOSE ) )
		      {
			final Crypto crypto = e.getCrypto();
			crypto.showInfo();
		      }
		    if( operation == Operation.EXTRACT )
		      {
			System.err.println( "\tExtract operation not yet implemented" );
		      }
		  }
		catch( Exception x )
		  {
		    System.out.println( e.getCrypto() + " \t" + e.name() + " -- ERROR: " + x.getMessage() );
		    if( options.contains( Option.VERBOSE ) )
		      {
			final Crypto crypto = e.getCrypto();
			crypto.showInfo();
		      }

		    // Obtain the entry's raw data (this is likely
		    // compressed, and the result of that is encrypted
		    final byte[] raw = e.raw();
		    System.err.println( "\tRAW size (unverified post-decrypt) = " + raw.length );
		    // Obtain this entry's cryptographical information
		    // and using that, decrypt the raw data using our
		    // password as the basis for the cryptographical
		    // key, BUT do NOT verify (false) the result: we
		    // know that verification failed (using convenient
		    // the "e.data(password)" call above)
		    final byte[] plain = e.getCrypto().decrypt( raw,
			                                        password,
			                                        false );
		    byte[] finished;
		    try
		      {
			finished = Entry.inflate( plain );
			System.err.println( "\tINFLATED (unverified stuff) = " + finished.length );
		      }
		    catch( Exception x2 )
		      {
			finished = plain;
			System.err.println( "\tINFLATED size = (failed to inflate)" );
		      }
		    final Crypto crypto = e.getCrypto();
		    if( ("manifest.rdf".equals( e.name() ) || "Configurations2/accelerator/current.xml".equals( e
			.name() )) &&
			"http://www.w3.org/2001/04/xmlenc#aes256-cbc".equals( crypto.getAlgorithmName() ) &&
			"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k"
			    .equals( crypto.getChecksumType() ) )
		      {
			System.err.println( new String( finished ) );
			System.err.println( "======================================================" );
			System.err.println( ">>>>> IF THE ABOVE LOOKS LIKE GOOD DATA THEN THE <<<<<" );
			System.err.println( ">>>>> CHECKSUM WAS BOGUS BUT THE DATA WAS GOOD!! <<<<<" );
			System.err.println( "======================================================" );
		      }
		  }
	      }
	    else
	      {
		final byte[] data = e.data();
		if( (data != null) && (data.length > 0) )
		  {
		    System.err.println( "--------------------------------------------------" );
		    System.out.println( "PLAIN \t" + e.name() + " (" + data.length + " bytes)" );
		    if( operation == Operation.EXTRACT )
		      {
			System.err.println( "\tExtract operation not yet implemented" );
		      }
		  }
	      }
	  }
      }
    finally
      {
	odf.close();
      }
  }


  private enum Operation
  {
    LIST,
    EXTRACT,
    LICENSE;
  }


  private enum Option
  {
    VERBOSE;
  }


  private Test()
  {
  }

  private static String password;
}
