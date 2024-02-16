import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayDeque;
import java.util.Deque;

import com.sun.net.httpserver.HttpExchange;

import web.WebServer.HttpShellServer;
import web.WebServer.IOStream;

/**
 * Accepts SQL Database commands and runs them on an SQL server
 * @author Derek McCants
 *
 */
public class HttpDebugSqlConsole extends HttpShellServer
{
	private SQLStream stream;
	
	public static String getExampleCommand()
	{
		return "SELECT * FROM Users;";
	}

	@Override
	public IOStream openTty(HttpExchange t) throws IOException {
		stream = new SQLStream();
		return new IOStream(stream.getInputStream(), stream.getOutputStream());
	}

	@Override
	public void closeTty() throws IOException {
		stream.closeDb();
	}

	@Override
	public void waitForExternalToClose() {
		while(!stream.canExit) ;
	}
	
	public class SQLStream
	{
		private Connection conn = null;
		public volatile boolean canExit = false;
		private StringBuilder inputBuf = new StringBuilder();
		//private Deque<Character> outputBuf = new ArrayDeque<Character>();
		OutputStreamWriter writer;
		PipedOutputStream pipeOut;
		PipedInputStream pipeIn;
		public InputStream getInputStream()
		{
			return pipeIn;
		}
		private SQLOutputStream output;
		public OutputStream getOutputStream()
		{
			return output;
		}
		private void print(String what)
		{
			try {
				pipeOut.write(what.getBytes());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			//outputBuf.addAll((what.chars().map((e) -> Character.valueOf((char) e))));
			//what.chars().forEachOrdered((e) -> outputBuf.addLast((char)e));
		}
		public void runSql(String what)
		{
			//print("Running SQL \"" + what + "\"");
			System.out.printf("[info] Running SQL \"%s\"\n", what);
			
			try {
				Statement st = conn.createStatement();
				ResultSet rs = st.executeQuery(what);
				ResultSetMetaData meta = rs.getMetaData();
				while(rs.next())
				{
					for(int i = 0; i < meta.getColumnCount(); i++)
					{
						print(meta.getColumnName(i + 1) + " = \"" + rs.getString(i + 1) + "\", ");
					}
					print("\n");
				}
				rs.close();
				st.close();
			} catch (SQLException e) {
				e.printStackTrace();
				print(e.getMessage());
			}
		}
		public SQLStream() throws IOException
		{
			pipeOut = new PipedOutputStream();
			pipeIn = new PipedInputStream(pipeOut, 16384);
			output = new SQLOutputStream();
			makeDatabaseConnection();
			
		}
		private class SQLOutputStream extends OutputStream
		{
			@Override
			public void write(int b) throws IOException {
				if(b == '\r' || b == '\n')
				{
					runSql(inputBuf.toString());
					inputBuf.setLength(0);
				}
				else
					inputBuf.append((char)b);
			}
		}
		public synchronized void makeDatabaseConnection() throws IOException
		{
			if(conn != null)
				return;
			try {
				conn = DriverManager.getConnection("jdbc:postgresql:");
			} catch (SQLException e) {
				throw new IOException(e);
			}
			print("SQL connected\n");
		}
		public void closeDb() throws IOException
		{
			try {
				if(conn != null)
				{
					conn.close();
					print("SQL connection closed\n");
				}
			} catch (SQLException e) {
				throw new IOException(e);
			} finally {
				canExit = true;
			}
		}
	}
}
