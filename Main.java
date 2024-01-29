import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;

import javax.sql.DataSource;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import web.WebServer;

public class Main
{
	/**
	 * The IP Address or hostname of the SQL Server
	 * <p>
	 * Use null for the default of "localhost"
	 */
	public static final String SQL_HOST = null;
	
	/**
	 * The name of the database to use
	 * <p>
	 * Use null for the default of the current username
	 */
	public static final String SQL_NAME = "asu";
	
	/**
	 * The username to log in to the SQL Server
	 * <p>
	 * Use null for the default of the current user
	 */
	public static final String SQL_USER = null;
	
	/**
	 * The password of the user, or null if not required
	 */
	public static final String SQL_PASS = "webserver";
	
	private static final DataSource dataSource = createDataSource();
	
	@SuppressWarnings("deprecation")
	private static final DataSource createDataSource()
	{
		org.postgresql.ds.PGPoolingDataSource src = new org.postgresql.ds.PGPoolingDataSource();
		if(SQL_HOST != null)
			src.setServerName(SQL_HOST);
		if(SQL_NAME != null)
			src.setDatabaseName(SQL_NAME);
		if(SQL_USER != null)
			src.setUser(SQL_USER);
		if(SQL_PASS != null)
			src.setPassword(SQL_PASS);
		// uncomment this if running on a different port
		//src.setPortNumber(5432);
		return src;
	}
		
	public static final Connection getDatabaseConnection() throws SQLException
	{
		return dataSource.getConnection();
	}
	
	public static void main(String[] args) {
		try {
			// initialize the WebServer, run on port 8080 and do NOT use HTTPS
			WebServer ws = new WebServer(8080, false);
			// create the SQLUserPassAuthenticator object, this object will authenticate the users
			SQLUserPassAuthenticator user = new SQLUserPassAuthenticator("login");
			ws.createContext("/", new WebServer.HttpHtmlResourceServer("/html/homepage.html"));
			ws.createContext("/index.html", new WebServer.HttpRedirector("/"));
			ws.createContext("/styles.css", new WebServer.HttpResourceServer("/html/styles.css"));
            ws.createContext("/favicon.ico", new WebServer.HttpResourceServer("/html/favicon.ico"));
            ws.createContext("/apple-touch-icon.png", new WebServer.HttpResourceServer("/html/apple-touch-icon.png"));
            ws.createContext("/asset", new WebServer.HttpResourceServer("/html/asset"));
            ws.createContext("/css", new WebServer.HttpResourceServer("/html/css"));
            ws.createContext("/fonts", new WebServer.HttpResourceServer("/html/fonts"));
            ws.createContext("/snek", new WebServer.HttpHtmlResourceServer("/html/snek.html"));
			ws.createContext("/sql", new HttpDebugSqlConsole());
			ws.createContext("/search", new SearchHandler());
			
			// the user must be logged in to view the below page, because
			// HomePageHandler extends CustomAuthorizedHttpHandler
			// the handler will only be called if the login succeeds
			ws.createContext("/home", new HomePageHandler(user));
			
			// the user must be logged in to view the below page
			// this is enforced with the AuthorizedHttpHandler object
			// use this way if you want to make sure the user is logged in, but do not need their username or any of their info
			ws.createContext("/other-home", new WebServer.AuthorizedHttpHandler(user, new WebServer.HttpHtmlResourceServer("/html/snek.html")));
			
			ws.createContext("/logout", new HttpHandler() {
				@Override
				public void handle(HttpExchange exchange) throws IOException {
					exchange.sendResponseHeaders(401, -1);
					exchange.close();
				}
			});
			ws.start();
			System.out.printf("Webserver started\n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
