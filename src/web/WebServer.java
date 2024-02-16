package web;

import util.Helper;
import util.HtmlEscapedInputStream;
import util.OS_Specific;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.BasicAuthenticator;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Deque;
import java.util.HashMap;
import java.util.IllegalFormatException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.function.BiConsumer;
import java.util.zip.ZipOutputStream;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * Implements an HTTP or HTTPS WebServer
 * @author Derek McCants
 * @version 2.2
 */
public class WebServer
{
	private HttpServer srv;
	private HttpServer httpsRedirectServer = null;
	public static HttpServer createHttpToHttpsRedirector(short fromPort, short toPort) throws IOException
	{
		HttpServer hs = HttpServer.create(new InetSocketAddress(fromPort), 0);
		hs.createContext("/", new HttpHandler() {
			@Override
			public void handle(HttpExchange exchange)
			{
				try {
					URI uri = exchange.getRequestURI();
					if(uri.getScheme() != null && !uri.getScheme().toLowerCase().equals("http"))
						throw new IOException("Unknown URI scheme " + uri.getScheme());
					URI nw = new URI("https", uri.getUserInfo(), uri.getHost() != null ? uri.getHost() : exchange.getLocalAddress().getHostString(), toPort, uri.getPath(), uri.getQuery(), uri.getFragment());
					exchange.getResponseHeaders().set("Location", nw.toString());
					exchange.sendResponseHeaders(308, -1);
					exchange.close();
					//System.err.println("Redirecting http -> https");
				} catch (Exception e) {
					//System.out.println("Failed to redirect http -> https!");
					e.printStackTrace();
				}
			}
		});
		return hs;
	}
	public boolean redirectHttpToHttps(int fromPort, int toPort)
	{
		try {
			httpsRedirectServer = createHttpToHttpsRedirector((short)fromPort, (short)toPort);
			httpsRedirectServer.start();
			return true;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}
	public boolean redirectHttpToHttps(int fromPort)
	{
		return redirectHttpToHttps(fromPort, srv.getAddress().getPort());
	}
	public WebServer(short port, boolean https) throws IOException
	{
		if(https)
		{
			HttpsServer hs = HttpsServer.create(new InetSocketAddress(port), 0);
			try {
				setupHttps(hs);
			} catch (Exception e) {
				throw new IOException(e);
			}
			srv = hs;
		}
		else
		{
			srv = HttpServer.create(new InetSocketAddress(port), 0);
		}
	}
	private static final char[] keypass   = "password".toCharArray();
	private static final char[] storepass = keypass; // set to null to skip checking integrity
	/** <pre>
	 * create a keystore by either:
	 * *** Generating a self-signed certificate/private key pair and import into keystore in 1 step ***
	 * keytool -genkeypair -keyalg RSA -alias self_signed -keypass <i>password</i> -keystore lig.jks -storepass <i>password</i>
	 * === OR ===
	 * *** Generate a private key ***
	 * openssl genrsa -out private.key 2048
	 * *** Generate the corresponding public key ***
	 * (Change der to pem, whatever form they need)
	 * openssl rsa -in private.key -pubout -outform der -out public.key
	 * 
	 * Get a certificate, by either:
	 * a) Creating a self-signed certificate with command:
	 *    openssl req -new -x509 -key private.key -out certificate.crt -days 1024
	 * === OR ===
	 * b) Send the CSR to a Certificate Authority
	 * 
	 * *** Create a pkcs12 keystore from the given certificate and private key ***
	 * openssl pkcs12 -export -in <path to certificate> -inkey <path to private key> -certfile <path to certificate> -out server.p12
	 * *** Create the JKS file from the pkcs12 file ***
	 * keytool -importkeystore -srckeystore server.p12 -srcstoretype pkcs12 -destkeystore lig.jks -deststoretype JKS
	 * *** (OPTIONAL) Change password of private key ***
	 * keytool -keypasswd -alias <alias name> -keystore <path to keystore>
	 * *** (OPTIONAL) Change alias of private key (set to "1" by default) ***
	 * keytool -changealias -keystore <path to keystore> -alias <current alias>
	 * </pre>
	 */
	private static final String keystoreFilename = "lig.jks";
	/**
	 * might need to set -Djdk.tls.acknowledgeCloseNotify=true in java options to prevent
	 * TLSv1.3 infinite loop in JDK 11 and 12
	 */
	private static void setupHttps(HttpsServer hs) throws NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, CertificateException, IOException, UnrecoverableKeyException, KeyManagementException
	{
		// initialize KeyStore
		SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		FileInputStream fis = new FileInputStream(keystoreFilename);
		ks.load(fis, storepass);
		
		// initialize KeyManagerFactory
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(ks, keypass);
		
		// initialize TrustManagerFactory
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);
		
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		hs.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
			public void configure(HttpsParameters params) {
				// initialize SSLContext
				SSLContext c = getSSLContext();
				SSLEngine engine = c.createSSLEngine();
				params.setNeedClientAuth(false);
				params.setCipherSuites(engine.getEnabledCipherSuites());
				params.setProtocols(engine.getEnabledProtocols());
				
				// get default parameters
				SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
				params.setSSLParameters(defaultSSLParameters);
			}
		});
		// TODO: overwrite keypass and storepass for better security
	}
	
	/**
	 * Starts the HTTP/S server and accepts incoming connections.
	 * <p>
	 * This method returns immediately.  Incoming connections are automatically
	 * handled using the registered handlers in new threads.  The Java program
	 * does not terminate until <code>stop()</code> is called, even if the main
	 * thread terminates.  If <code>stop()</code> is never called, then the
	 * program never exits.
	 */
	public void start()
	{
		srv.setExecutor(Executors.newCachedThreadPool());
		srv.start();
	}
	
	/**
	 * Immediately stops the HTTP/S server.  Pending connections are rejected,
	 * and existing connections are aborted and closed.  New connections are
	 * refused.
	 */
	public void stop()
	{
		srv.stop(0);
	}
	
	/**
	 * Assigns the given path to the appropriate handler.  When a new connection
	 * is made requesting the given path, then control flow is passed to the handler
	 * by calling its <code>handle()</code> method.
	 * <p>
	 * For example, a call to:
	 * <code>createContext("/path", someJavaObject);</code>
	 * means that any time a user navigates to http://&lt;whatever&gt;/path, then
	 * the WebServer will call <code>someJavaObject.handle()</code> to process the
	 * user's request.
	 * @param ctx A <code>String</code> representing the path to be handled.  Note
	 * that any path starting with this will also be handled (so the handler for
	 * "/path" will handle "/path" but also "/path/here")
	 * @param handler The <code>HttpHandler</code> that should handle these requests
	 */
	public void createContext(String ctx, HttpHandler handler)
	{
		srv.createContext(ctx, handler);
	}
	
	public void removeContext(String ctx)
	{
		srv.removeContext(ctx);
	}
	
	public WebServer(int port, boolean https) throws IOException
	{
		this((short)port, https);
	}
	
	public static abstract class UserPassAuthenticator extends BasicAuthenticator
	{
		public UserPassAuthenticator(String realm)
		{
			super(realm);
		}
		protected String loggedUser;
		public String getLoggedUser()
		{
			return loggedUser;
		}
		public abstract boolean checkCredentials(String username, String password);
	}
	
	public static class AnyOfBasicAuthenticator extends UserPassAuthenticator
	{
		public AnyOfBasicAuthenticator(String realm, BasicAuthenticator... authenticators)
		{
			super(realm);
			auth = authenticators;
		}

		BasicAuthenticator[] auth;

		@Override
		public boolean checkCredentials(String username, String password)
		{
			for(BasicAuthenticator a : auth)
				if(a != null)
					if(a.checkCredentials(username, password))
					{
						loggedUser = username;
						return true;
					}
			return false;
		}
	}
	
	/**
	 * Checks a username and password against loaded credentials
	 * <p>
	 * For extra "security", the username and password is stored in memory as a
	 * SHA-256 hash, so even dumping the JVM's memory should (hopefully) not
	 * contain any usable cleartext credentials
	 * @author Derek McCants
	 *
	 */
	public static class HardcodedUserPassAuthenticator extends UserPassAuthenticator
	{
		protected ConcurrentMap<ArrayWrapper<Byte>, ArrayWrapper<Byte>> creds;
		public HardcodedUserPassAuthenticator(String realm)
		{
			super(realm);
			creds = new ConcurrentHashMap<ArrayWrapper<Byte>, ArrayWrapper<Byte>>();
		}
		private static final MessageDigest getMessageDigest()
		{
			try {
				return MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace(); // this should never happen since java spec requires SHA-256 to be supported!
				try {
					return MessageDigest.getInstance("SHA-1");
				} catch (NoSuchAlgorithmException e1) {
					e1.printStackTrace();
					try {
						return MessageDigest.getInstance("MD5");
					} catch (NoSuchAlgorithmException e2) {
						e2.printStackTrace();
						return null;
					}
				}
			}
		}
		
		/**
		 * Wraps byte[] -> Byte[]
		 * @param lowercase an array of byte (lowercase)
		 * @return an array of Byte (uppercase)
		 */
		private static final Byte[] primativeByteArrayToByteObjectArray(byte[] lowercase)
		{
			Byte[] uppercase = new Byte[lowercase.length];
			for(int index = 0; index < lowercase.length; index++)
				uppercase[index] = lowercase[index];
			return uppercase;
		}
		
		public static final ArrayWrapper<Byte> hash(String str)
		{
			return new ArrayWrapper<Byte>(primativeByteArrayToByteObjectArray(getMessageDigest().digest(str.getBytes())));
		}
		
		/**
		 * Creates a valid username/password combo for logging into this
		 * <code>HardcodedUserPassAuthenticator</code>
		 * <p>
		 * <b>IMPORTANT:</b> This method provides no real security since the
		 * cleartext password is visible in the source code.  For security
		 * conscious applications, <code>adduserHashed()</code> should be used
		 * wherever possible!
		 * @param username The username to create
		 * @param password The new cleartext password for this user
		 * @return A reference to this
		 * <code>HardcodedUserPassAuthenticator</code>
		 * @deprecated This method is very insecure, since the cleartext
		 * password is present in the source code.  This is only intended for
		 * "security optional" applications, and <code>adduserHashed()</code>
		 * should be preferred wherever possible!
		 */
		@Deprecated
		public HardcodedUserPassAuthenticator adduser(String username, String password)
		{
			creds.put(hash(username), hash(password));
			return this;
		}
		
		/**
		 * Creates a valid username/password combo for logging into this
		 * <code>HardcodedUserPassAuthenticator</code>
		 * <p>
		 * Note that <code>hashed_password</code> should be a valid SHA-256
		 * hash, or else this user will be unable to login!
		 * @param username The username to create
		 * @param hashed_password The raw bytes of the SHA-256 hash of this
		 * user
		 * @return A reference to this
		 * <code>HardcodedUserPassAuthenticator</code>
		 */
		public HardcodedUserPassAuthenticator adduserHashed(String username, byte[] hashed_password)
		{
			creds.put(hash(username), new ArrayWrapper<Byte>(primativeByteArrayToByteObjectArray(hashed_password)));
			return this;
		}
		
		/**
		 * Creates a valid username/password combo for logging into this
		 * <code>HardcodedUserPassAuthenticator</code>
		 * <p>
		 * Note that <code>hashed_password</code> should be a valid SHA-256
		 * hash, or else this user will be unable to login!
		 * @param username The username to create
		 * @param hashed_password The new password for this user, as a SHA-256
		 * hash
		 * @return A reference to this
		 * <code>HardcodedUserPassAuthenticator</code>
		 */
		public HardcodedUserPassAuthenticator adduserHashed(String username, String hashed_password)
		{
			return adduserHashed(username, Helper.hexStringToByteArray(hashed_password));
		}
		
		/**
		 * Deletes a user.  After this operation, this user will be unable to
		 * login to this <code>HardcodedUserPassAuthenticator</code>
		 * <p>
		 * This method has no affect if the user does not exist.
		 * @param username The username to delete
		 * @return A reference to this
		 * <code>HardcodedUserPassAuthenticator</code>
		 */
		public HardcodedUserPassAuthenticator deluser(String username)
		{
			creds.remove(hash(username));
			return this;
		}

		@Override
		public boolean checkCredentials(String username, String password)
		{
			if(!creds.containsKey(hash(username)))
				return false;
			if(!creds.get(hash(username)).equals(hash(password)))
				return false;
			loggedUser = username;
			return true;
		}
	}
	
	private static class ArrayWrapper<T>
	{
		public T[] data;
		public ArrayWrapper(T[] data)
		{
			this.data = data;
		}
		public int hashCode()
		{
			return Arrays.hashCode(data);
		}
		public boolean equals(T[] other)
		{
			return Arrays.deepEquals(data, other);
		}
		public boolean equals(ArrayWrapper<T> other)
		{
			return equals(other.data);
		}
		@SuppressWarnings("unchecked")
		public boolean equals(Object other)
		{
			if(other.getClass() == this.getClass())
				return equals((ArrayWrapper<T>)other);
			return false;
		}
	}
	
	public static abstract class CustomAuthorizedHttpHandler implements HttpHandler
	{
		private UserPassAuthenticator auth;
		public CustomAuthorizedHttpHandler(UserPassAuthenticator ba)
		{
			auth = ba;
		}
		
		public void handle(HttpExchange t)
		{
			try {
				Authenticator.Result result = auth.authenticate(t);
				if(result instanceof Authenticator.Success)
				{
					handleAuthorized(t, auth.getLoggedUser());
				}
				else if(result instanceof Authenticator.Failure)
				{
					t.sendResponseHeaders(((Authenticator.Failure)result).getResponseCode(), -1);
					t.close();
					System.out.printf("[warn] failed authentication from %s\n", t.getRemoteAddress());
				}
				else if(result instanceof Authenticator.Retry)
				{
					
					t.sendResponseHeaders(((Authenticator.Retry)result).getResponseCode(), -1);
					t.close();
					System.out.printf("[warn] retry authentication from %s\n", t.getRemoteAddress());
				}
				else
					throw new IOException("Unknown authenticator result!");
			} catch (Exception e) {
				e.printStackTrace();
				WebServer.handleErrorChecked(t, 500, e);
			}
		}
		public abstract void handleAuthorized(HttpExchange t, String user) throws IOException;
	}
	
	public static class CustomAuthorizedHttpHandlerLambda extends CustomAuthorizedHttpHandler
	{
		BiConsumer<HttpExchange, String> handler;
		public CustomAuthorizedHttpHandlerLambda(UserPassAuthenticator ba, BiConsumer<HttpExchange, String> handler)
		{
			super(ba);
			this.handler = handler;
		}
		public void handleAuthorized(HttpExchange t, String user)
		{
			handler.accept(t, user);
		}
	}
	
	public static class AuthorizedHttpHandler extends CustomAuthorizedHttpHandler implements HttpHandler
	{
		HttpHandler h;
		public AuthorizedHttpHandler(UserPassAuthenticator ba, HttpHandler ha)
		{
			super(ba);
			h = ha;
		}

		@Override
		public void handleAuthorized(HttpExchange t, String user) throws IOException
		{
			h.handle(t);
		}
	}
	
	public static abstract class HttpUploader implements HttpHandler
	{
		public HttpUploader()
		{
		}
		
		public void handle(HttpExchange t)
		{
			//System.out.println("===== Started new upload =====");
			/*String method = t.getRequestMethod();
			if(!(method.equals("POST") || method.equals("PUT")))
			{
				ErrorServer es = new ErrorServer(405, new Exception("This endpoint is expecting an upload, but method is " + method + "!"));
				es.handle(t);
				return;
			}*/
			Headers head = t.getRequestHeaders();
			String boundary = null;
			List<String> contenttype = head.get("Content-Type");
			if(contenttype == null || contenttype.size() == 0)
			{
				WebServer.handleErrorChecked(t, 415, new Exception("Missing Content-Type header from upload"));
				return;
			}
			for(String s : contenttype)
			{
				String[] items = s.split(";");
				for(String item : items)
				{
					if(item.trim().toLowerCase().startsWith("boundary"))
					{
						int equals = item.indexOf('=');
						boundary = item.substring(equals + 1);
						break;
					}
				}
				if(boundary != null)
					break;
			}
			if(boundary == null)
			{
				WebServer.handleErrorChecked(t, 415, new Exception("Missing boundary!"));
				return;
			}
			boundary = ("\r\n--" + boundary);
			//System.out.println("boundary is \"" + boundary + "\"");
			BufferedHttpMultiPartFormReader bhmpfr = new BufferedHttpMultiPartFormReader(t.getRequestBody(), boundary.getBytes());
			//ByteArrayOutputStream baos = new ByteArrayOutputStream();
			//PrintWriter pw = new PrintWriter(baos);
			//List<String> analysi = new ArrayList<String>();
			try {
				while(bhmpfr.nextFile())
					handleFile(t, bhmpfr, bhmpfr.getAttr());
				doHandle(t);
			} catch (Exception e) {
				e.printStackTrace();
				try {
					byte[] waste = new byte[16384];
					while(t.getRequestBody().read(waste) >= 0)
						;
					waste = null;
					t.close();
				} catch(Exception e1) {
					; // Do nothing
				}
				WebServer.handleErrorChecked(t, 500, e);
			}
		}
		
		public abstract void handleFile(HttpExchange t, InputStream file, Map<String, String> attr) throws Exception;
		public abstract void doHandle(HttpExchange t);
		
		private class BufferedHttpMultiPartFormReader extends InputStream
		{
			private byte[] b;
			//private Deque<Integer> buffer;
			private InputStream is;
			private Map<String, String> attr;
			public Map<String, String> getAttr()
			{
				return attr;
			}
			private boolean eof;
			private boolean firstfile;
			public BufferedHttpMultiPartFormReader(InputStream is, byte[] boundary)
			{
				this.is = new BufferedInputStream(is);
				b = boundary;
				//buffer = new LinkedList<Integer>();
				eof = false;
				firstfile = true;
			}
			
			/*public String getCurrentFiletype()
			{
				return filetype;
			}
			
			public String getCurrentFilename()
			{
				return filename;
			}*/
			
			public boolean nextFile() throws IOException
			{
				//System.out.println("in nextFile()");
				//if(!firstfile)
				while(read() > -1)
					;
				is.mark(2);
				if(!(is.read() == '\r' && is.read() == '\n'))
					is.reset();
				//firstfile = false;
				//System.out.println("ok, at the end of previous file");
				eof = false;
				//i = 0;
				//buffer.clear();
				StringBuilder b = new StringBuilder();
				b.append(' ');
				List<String> lines = new LinkedList<String>();
				
				for(int n = 0; n < 1 || b.length() > 0; n++)
				{
					b.setLength(0);
					int q;
					while((q = is.read()) >= 0 && q != '\r')
						b.append(((char)q));
					if(q < 0)
						return false;
					lines.add(b.toString().trim());
					if(q == '\r')
						if(is.read() != '\n')
						{
							System.err.printf("in nextFile(), expected \\n, but got %c (ASCII %d)\n", (char)q, q);
							System.exit(1);
						}
				}
				//System.out.println("The lines we got from nextFile() are: ");
				Iterator<String> i = lines.iterator();
				String l;
				int eq;
				attr = new HashMap<String, String>();
				while(i.hasNext())
				{
					l = i.next();
					//System.out.printf("line [] = \"%s\"\n", l);
					
					if(l.trim().toLowerCase().matches("content[-_]disposition[:]?[\\s]*form[-_]data;.*"))
					{
						String[] stuff = l.split(";");
						for(String tokens : stuff)
						{
							if((eq = tokens.indexOf('=')) < 0)
								continue;
							String tokname = tokens.substring(0, eq).trim();
							attr.put(tokname,tokens.substring(eq + 1).replace('\"', ' ').trim());
						}
					}
				}
				return true;
			}
			
			@Override
			public int read() throws IOException
			{
				//System.out.println("called read()");
				if(eof)
				{
					//System.out.println("eof is true");
					return -1;
				}
				int c = is.read();
				//System.out.printf("underlying stream returned 0x%02x (%c)\n", c, c);
				if(c < 0)
				{
					eof = true;
					return -1;
				}
				if(c != b[0])
					return c;
				
				is.mark(b.length);
				for(int i = 1; i < b.length; ++i)
				{
					//System.out.printf("i = %d\n", i);
					int q = is.read();
					if(q < 0 || q != b[i])
					{
						is.reset();
						return c;
					}
				}
				//in.reset();
				//System.out.println("found boundry");
				eof = true;
				return -1;
			}
			
			
			
			@Override
			public void close() throws IOException
			{
				//System.out.println("in close()");
				is.close();
			}
		}
	}
	
	public static final void redirect(HttpExchange t, String destURL) throws IOException
	{
		t.getResponseHeaders().add("Location", destURL);
		t.sendResponseHeaders(303, -1);
		t.getResponseBody().close();
	}
	
	public static final void redirectChecked(HttpExchange t, String destURL)
	{
		try {
			redirect(t, destURL);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static class HttpRedirector implements HttpHandler
	{
		private String dest;
		public HttpRedirector(String destURL)
		{
			dest = destURL;
		}
		public void handle(HttpExchange t)
		{
			redirectChecked(t, dest);
		}
	}
	
	public static class DebugErrorServer implements HttpHandler
	{
		public void handle(HttpExchange t)
		{
			HttpContext ctx = t.getHttpContext();
			String uri = null;
			try {
				uri = URLDecoder.decode(t.getRequestURI().toString(), StandardCharsets.UTF_8.name());
			} catch (UnsupportedEncodingException e1) {
				// This will never happen
				e1.printStackTrace();
			}
			if(!uri.startsWith(ctx.getPath()))
				System.err.println("????");
			String[] important = uri.substring(ctx.getPath().length()).split("/");
			
			int code = Integer.parseInt(important[0]);
			WebServer.handleErrorChecked(t, code, important.length > 1 ? new Exception(important[1]) : null);
		}
	}
	
	/**
	 * Handles the passed exception and displays a descriptive error message
	 * of the problem to the user over HTTP, using the specified
	 * {@link HttpExchange}.
	 * @param t The {@link HttpExchange} to send the response to
	 * @param n The HTTP error code to used (i.e. 404 for Not Found, 500 for
	 * Internal Server Error, etc.)
	 * @param e The {@link Exception} that caused the problem, or
	 * <code>null</code> if it is not known or unavailable
	 */
	public static final void handleErrorChecked(HttpExchange t, int n, Exception e)
	{
		Date d = new Date();
		HttpContext ctx = t.getHttpContext();
		System.out.printf("[fail] [%s] Serving error %d for URI \"%s\"\n", ctx.getPath(), n, t.getRequestURI().toString());
		HtmlPageFactory pw = new HtmlPageFactory();
		
		try {
			pw.createTitle("Error");
			pw.startMainBody();
			pw.print("<div class=\"col-lg-12\">");
			pw.print(	"<div class=\"row\">");
			pw.print(		"<div class=\"col-lg-12\">");
			pw.printf(			"<p style=\"text-align:center;\">Error %d %s</p>", n, errmsg.containsKey(n) ? errmsg.get(n) : "Unknown Error");
			pw.print(		"</div>");
			pw.print(	"</div>");
			pw.print(	"<div class=\"row\">");
			pw.print(		"<div class=\"col-lg-12\">");
			
			pw.print("<p>An error occured while processing the request.  The below technical information and meme may be helpful in troubleshooting and identifying the cause of the error.</p>");
			pw.printf("<img src=\"https://http.%s/%d.jpg\"><br>", Math.random() < 0.5 ? "cat" : "dog", n);
			pw.print("<pre class=\"error\"><p>");
			pw.printf("Error Code:      %d %s<br/>", n, errmsg.containsKey(n) ? errmsg.get(n) : "Unknown Error");
			pw.printf("Requested URI:   %s<br/>", t.getRequestURI().toString());
			pw.printf("Request Method:  %s<br/>", t.getRequestMethod());
			Headers header = t.getRequestHeaders();
			pw.printf("Headers (%d total)<br/>", header.size());
			header.forEach((name, values) -> {
				if(name.toLowerCase().trim().equals("authorization"))
					pw.printf("    %s: <i>This header censored for security reasons</i><br/>", name);
				else
					pw.printf("    %s: [ %s ]<br/>", name, String.join(" ", values));
			});
			pw.printf("Context Path:    %s<br/>", ctx.getPath());
			pw.printf("Occurred:        %s<br/>", d.toString());
			pw.printf("Temp Directory:  %s<br/>",System.getProperty("java.io.tmpdir"));
			pw.printf("Java Version:    Java %s (%s)<br/>",System.getProperty("java.version"), System.getProperty("java.vendor"));
			pw.printf("JVM Info:        %s %s (%s)<br/>", System.getProperty("java.vm.name"), System.getProperty("java.vm.version"), System.getProperty("java.vm.vendor"));
			pw.printf("Server OS Info:  %s (version %s) on %s<br/>", System.getProperty("os.name"),System.getProperty("os.version"),System.getProperty("os.arch"));
			if(e != null)
			{
				pw.print("Stack Trace:<br/>");
				pw.print(e);
			}
			else
			{
				pw.println("That's an error.  That's all we know :(");
			}
			
			pw.print(		"</div>");
			pw.print(	"</div>");
			pw.print("</div>");
			pw.closeAllElements();
			pw.sendResponse(n, t);
			pw.close();
			System.out.printf("[warn] [%s] Served error successfully\n", ctx.getPath());
		} catch (Exception ex) {
			System.err.printf("[fail] [%s] Also failed to serve error page, some sort of castrophic failure has occurred!\n", ctx.getPath());
			ex.printStackTrace();
		}
	}
	
	/**
	 * Historically, this class was used to handle errors and notify the user
	 * of problems in a descriptive format over HTTP.  However, this class is
	 * no longer used except in {@link legacy_sss.SSS_Session}.
	 * <p>
	 * In new code, use {@link WebServer#handleErrorChecked(HttpExchange, int, Exception)}
	 * to reduce unnecessary object allocation
	 * @author Derek McCants
	 * @deprecated Use {@link WebServer#handleErrorChecked(HttpExchange, int, Exception)}
	 * instead to avoid unnecessary object allocation
	 */
	@Deprecated
	public static class ErrorServer implements HttpHandler
	{
		int n;
		Exception e;
		public ErrorServer(int error, Exception exception)
		{
			n = error;
			e = exception;
		}
		
		@Override
		public void handle(HttpExchange t)
		{
			handleErrorChecked(t, n, e);
		}
	}
	
	public static abstract class NewAbstractHttpFileServer<T> implements HttpHandler
	{
		int failcode; // getRequestedFileFromBase should set this on failure
		public abstract T getRequestedFileFromBase(String concat) throws Exception;
		public abstract T addSuffixToBase(T base, String concat) throws Exception;
		private static final String readOnlyAllowOptions = "OPTIONS, GET, HEAD";
		private static final String readWriteAllowOptions = "OPTIONS, GET, HEAD, PUT, POST, DELETE";
		public abstract String getName(T fileObject);
		/**
		 * Return -1 if not supported
		 * @param fileObject
		 * @return
		 */
		public abstract long getFreeSpace(T fileObject);
		/**
		 * Return -1 if not supported
		 * @param fileObject
		 * @return
		 */
		public abstract long getTotalSpace(T fileObject);
		public abstract boolean isDirectory(T fileObject);
		public abstract boolean isRegularFile(T fileObject);
		/**
		 * null for access denied, empty array for empty folder
		 * @param fileObject
		 * @return
		 */
		public abstract T[] getChildren(T fileObject);
		public abstract long estimateSize(T fileObject);
		public abstract boolean lastModifiedSupported();
		public abstract Date getLastModified(T fileObject);
		public abstract void deleteFile(T fileObject);
		public abstract void renameFile(T fileObject, String newName);
		/**
		 * Opens an InputStream to read from a file
		 * @param fileObject
		 * @return
		 * @throws IOException
		 */
		public abstract InputStream openInputStream(T fileObject) throws IOException;
		/**
		 * Opens an OutputStream to write to a file
		 * @param fileObject
		 * @return
		 * @throws IOException
		 */
		public abstract OutputStream openOutputStream(T fileObject) throws IOException;
		/**
		 * Creates a directory with the specified name
		 * @param fileObject
		 * @throws IOException
		 */
		public abstract void createDirectory(T fileObject) throws IOException;
		
		private HtmlPageFactory printDir(T o, String uri, String parentUri, boolean writable) throws IOException
		{
			HtmlPageFactory pw = new HtmlPageFactory();
			pw.print("<section id=\"featured\" class=\"\">");
			pw.print(	"<div class=\"cta-text\">");
			pw.print(		"<div>");
			pw.print(			"<p style=\"font-size: 36px; color:#656565;\">Directory Listing</p>");
			
			long freeSpace = getFreeSpace(o);
			long totalSpace = getTotalSpace(o);
			if(freeSpace >= 0 && totalSpace >= 0)
			{
				pw.print("<span style=\"margin-left: 20px;\">");
				double percentFree = 100 * (((double)freeSpace) / totalSpace);
				if(percentFree < 5)
					pw.print("<b style=\"color: red;\">");
				pw.printf("%s free / %s total (%.2f%% free)", Helper.prettySize(freeSpace), Helper.prettySize(totalSpace), percentFree);
				if(percentFree < 5)
					pw.print("</b>");
				pw.print("</span>");
			}
			pw.print(		"</div>");
			pw.print(	"</div>");
			pw.print("</section>");
			
			pw.print("<section id=\"content\">");
			pw.print(	"<div class=\"container\">");
			pw.print(		"<div class=\"row fadeInUpBig\">");
			pw.print(			"<div class=\"col-lg-12\">");
			pw.print(				"<div class=\"row\">");
			pw.print(					"<div class=\"col-lg-12\">");
			pw.printf(						"<p style=\"text-align:center; word-wrap: break-word;\">%s</p>", Helper.escapeHTML(uri));
			pw.print(					"</div>");
			pw.print(				"</div>");
			pw.print(				"<div class=\"row\">");
			pw.print(					"<div class=\"col-lg-12\">");
			
			pw.print(		"<table class=\"table table-hover\" style=\"font-size: small\">");
			pw.print(			"<tbody>");
			pw.print(				"<tr>");
			int effectiveCol = 3;
			pw.print(					"<th valign=\"top\" style=\"white-space: nowrap; width: 32px;\"> </th>");
			pw.print(					"<th style=\"word-wrap: break-word; word-break: break-all;\">Name</th>");
			if(lastModifiedSupported())
			{
				pw.print(				"<th style=\"text-align: right;\">Last Modified</th>");
				effectiveCol++;
			}
			pw.print(					"<th style=\"text-align: right;\">Size</th>");
			if(writable)
			{
				effectiveCol += 2;
				pw.print(					"<th style=\"text-align: right;\"></th>"); // Rename
				pw.print(					"<th style=\"text-align: right;\"></th>"); // Delete
			}
			pw.print(				"</tr>");
			String urlEncodedURI = Helper.urlEncodeExceptSlash(uri);
			if(writable)
			{
				
				pw.print(				"<tr>");
				pw.printf(					"<form action=\"%s\" enctype=\"multipart/form-data\" method=\"POST\">", urlEncodedURI);
				// TODO: remove this
				pw.print(						"<input type=\"hidden\" id=\"dummy\" name=\"dummy\" value=\"dummy\">");
				pw.print(						"<td valign=\"top\">");
				pw.print(							"<img src=\"/asset/icon/unknown.png\" style=\"width: 24px;height: auto;\">");
				pw.print(						"</td>");
				pw.printf(						"<td colspan=\"%d\">", effectiveCol - 2);
				//<form action="/sss/analyze?id=$_MY_SESSION_ID$" enctype="multipart/form-data" method="POST">
				//<label for="myfile">Project File(s):</label>
				//<input type="file" id="myfile" name="myfile" multiple>
				pw.print(							"<label for=\"upload\">Upload file(s):</label>");
				pw.print(							"<input type=\"file\" id=\"upload\" name=\"upload\" multiple>");
				pw.print(						"</td>");
				pw.print(						"<td>");
				pw.print(							"<button type=\"submit\" class=\"btn btn-theme animated\">Upload</button>");
				pw.print(						"</td>");
				pw.print(					"</form>");
				pw.print(				"</tr>");
				
				pw.print(				"<tr>");
				pw.printf(					"<form action=\"%s\" enctype=\"multipart/form-data\" method=\"POST\">", urlEncodedURI);
				// TODO: remove this
				pw.print(						"<input type=\"hidden\" id=\"dummy\" name=\"dummy\" value=\"dummy\">");
				pw.print(						"<td valign=\"top\">");
				pw.print(							"<img src=\"/asset/icon/folder.png\" style=\"width: 24px;height: auto;\">");
				pw.print(						"</td>");
				pw.printf(						"<td colspan=\"%d\">", effectiveCol - 2);
				pw.print(							"<label for=\"file\">Create a folder: </label>");
				pw.print(							"<input id=\"file\" name=\"file\">");
				pw.print(						"</td>");
				pw.print(						"<td>");
				pw.print(							"<button type=\"submit\" id=\"create\" name=\"create\" class=\"btn btn-theme animated\">Create</button>");
				pw.print(						"</td>");
				pw.print(					"</form>");
				pw.print(				"</tr>");
			}
			pw.printf(				"<tr class=\"clickable-row\" data-href=\"%s\" onclick=\"window.location=this.dataset.href\">", parentUri);
			pw.print(					"<td valign=\"top\">");
			pw.print(						"<img src=\"/asset/icon/folder.png\" style=\"width: 24px;height: auto;\">");
			pw.print(					"</td>");
			pw.printf(					"<td colspan=\"%d\">", effectiveCol - 1);
			if(parentUri.isEmpty())
				pw.printf(						"<a href=\"/\">Navigate up a directory</a>");
			else
				pw.printf(						"<a href=\"%s\">Navigate up a directory</a>", parentUri);
			pw.print(					"</td>");
			pw.print(				"</tr>");
			T[] children = getChildren(o);
			if(children == null)
			{
				pw.printf("<tr><td colspan=\"%d\"><i>Access was denied.</i></td></tr>", effectiveCol);
			}
			else if(children.length == 0)
			{
				pw.printf("<tr><td colspan=\"%d\"><i>This directory is empty.</i></td></tr>", effectiveCol);
			}
			else
			{
				for(T child : children)
				{
					String name = getName(child);
					String ext = "unknown";
					int dotindex;
					if((dotindex = name.lastIndexOf('.')) >= 0)
						ext = name.substring(dotindex + 1);
					String icon = isDirectory(child) ? "folder" : ext.toLowerCase();
					InputStream is;
					if((is = getClass().getResourceAsStream("/html/asset/icon/" + icon + ".png")) != null)
						is.close();
					else
						icon = "unknown";
					String newuri = uri;
					char c = uri.charAt(uri.length() - 1);
					if(c == '/' || c == '\\')
						;
					else
						newuri += "/";
					newuri += name;
					newuri = Helper.urlEncodeExceptSlash(newuri);
					String sz = "";
					if(!isDirectory(child))
					{
						if(!isRegularFile(child))
							sz = "infinity";
						else
							sz = Helper.prettySize(estimateSize(child));
					}
					//pw.printf("<tr class=\"clickable-row\" data-href=\"%s\" onclick=\"window.location=this.dataset.href\">", newuri);
					pw.printf("<tr class=\"clickable-row\" data-href=\"%s\">", newuri);
					pw.print(	"<td valign=\"top\">");
					pw.printf(		"<a href=\"%s\">", newuri);
					pw.printf(			"<img src=\"/asset/icon/%s.png\" style=\"width: 24px;height: auto;\">", icon);
					pw.print(		"</a>");
					pw.print(	"</td>");
					pw.print(	"<td style=\"word-wrap: break-word; word-break: break-all;\">");
					pw.printf(		"<b><a href=\"%s\">%s</a></b>", newuri, Helper.escapeHTML(name));
					pw.print(	"</td>");
					if(lastModifiedSupported())
						pw.printf(	"<td align=\"right\">%s</td>", getLastModified(child).toString());
					pw.printf(	"<td align=\"right\">%s</td>", sz);
					if(writable)
					{
						pw.printf("<form action=\"%s\" enctype=\"multipart/form-data\" method=\"POST\">", urlEncodedURI);
						// TODO: remove this
						pw.print(	"<input type=\"hidden\" id=\"dummy\" name=\"dummy\" value=\"dummy\">");
						pw.printf(	"<input type=\"hidden\" name=\"file\" value=\"%s\">", Helper.escapeHTML(name));
						pw.print(	"<td>");
						pw.print(		"<input name=\"renameto\">");
						pw.print(		"<button type=\"submit\" id=\"rename\" name=\"rename\" class=\"btn btn-theme animated\">Rename</button>");
						pw.print(	"</td>");
						pw.print(	"<td>");
						pw.printf(		"<button type=\"submit\" id=\"delete\" name=\"delete\" onclick=\"return confirm('Are you sure you want to delete \\\'%s\\\'?');\" class=\"btn btn-theme animated\">Delete</button>", Helper.escapeHTML(name));
						pw.print(	"</td>");
						pw.print("</form>");
						pw.print("</td>");
					}
					pw.print("</tr>");
				}
			}
			//pw.print("<tr><th colspan=\"4\"><hr></th></tr>");
			pw.print("</tbody></table>");
			pw.print(					"</div>");
			pw.print(				"</div>");
			pw.print(			"</div>");
			pw.print(		"</div>");
			pw.print(	"</div>");
			pw.print("</section>");
			return pw;
		}
		protected void doHandle(HttpExchange t, long cache, int code, boolean writable)
		{
			System.out.printf("[info] [debug] [NewAbstractHttpFileServer<T>] Started doHandle(HttpExchange, %d, %d, %s)\n", cache, code, String.valueOf(writable));
			String method = t.getRequestMethod().toUpperCase(Locale.ROOT);
			HttpContext ctx = t.getHttpContext();
			String uri = null;
			try {
				uri = URLDecoder.decode(t.getRequestURI().normalize().toString(), StandardCharsets.UTF_8);
			} catch (Exception e) {
				WebServer.handleErrorChecked(t, 400, e);
				return;
			}
			System.out.printf("[info] [debug] [NewAbstractHttpFileServer<T>] Decoded URI is \"%s\"\n", uri);
			//uri = t.getRequestURI().normalize().toString();
			String cph = ctx.getPath();
			Headers sendhead = t.getResponseHeaders();
			String requestedFileSuffix = "";
			if(!uri.startsWith(cph))
				System.err.println("[warn] [NewAbstractHttpFileServer<T>.doHandle()] Wait, something happened in NewAbstractHttpFileServer<T>!! uri = \"" + uri + "\" and context is \"" + cph + "\"");
			requestedFileSuffix = uri.substring(cph.length());
			System.out.printf("[info] [debug] [NewAbstractHttpFileServer<T>] requestedFileSuffix = \"%s\"\n", requestedFileSuffix);
			T o = null;
			try {
				failcode = 500;
				o = getRequestedFileFromBase(requestedFileSuffix);
			} catch (Exception e) {
				WebServer.handleErrorChecked(t, failcode, e);
				return;
			}
			String parentUri = null;
			int lastSlash = uri.lastIndexOf('/');
			if(lastSlash < 0)
				parentUri = uri + "/..";
			else
				parentUri = uri.substring(0, lastSlash);
			/*try {
				parentUri = URLDecoder.decode(new URI(t.getRequestURI().toString() + "/..").normalize().toString(), StandardCharsets.UTF_8);
				
			} catch (URISyntaxException e1) {
				// TODO Auto-generated catch block
				new ErrorServer(400, e1).handle(t);
				return;
			}*/
			//parentUri = Helper.urlEncode(parentUri);
			parentUri = Helper.urlEncodeExceptSlash(parentUri);
			if(method.equals("GET") || method.equals("HEAD"))
			{
				if(cache > 0)
					sendhead.add("Cache-Control", "max-age=" + cache);
				if(isDirectory(o))
				{
					sendhead.add("Content-Type", "text/html");
					try {
						if(method.equals("HEAD"))
						{
							t.sendResponseHeaders(code, -1);
							return;
						}
						HtmlPageFactory pw = printDir(o, uri, parentUri, writable);
						pw.sendResponse(200, t);
						pw.close();
					} catch (IOException e) {
						e.printStackTrace();
						WebServer.handleErrorChecked(t, 500, e);
					} catch (IllegalFormatException e) {
						e.printStackTrace();
						WebServer.handleErrorChecked(t, 500, e);
					}
				}
				else
				{
					InputStream is = null;
					try {
						is = openInputStream(o);
						if(method.equals("HEAD"))
						{
							t.sendResponseHeaders(code, -1);
							is.close();
							return;
						}
						t.sendResponseHeaders(code, estimateSize(o));
						BufferedOutputStream os = new BufferedOutputStream(t.getResponseBody());
						is.transferTo(os);
						is.close();
						os.flush();
						os.close();
					} catch (FileNotFoundException e) {
						WebServer.handleErrorChecked(t, 404, e);
						return;
					} catch (IOException e) {
						WebServer.handleErrorChecked(t, 500, e);
						return;
					}
				}
			}
			else if((method.equals("POST") || method.equals("PUT") || method.equals("DELETE")) && !writable)
			{
				WebServer.handleErrorChecked(t, 405, new UnsupportedOperationException("Requested write to read-only content at " + uri));
			}
			else if(method.equals("POST"))
			{
				new PostFileHandler(o, uri, parentUri).handle(t);
			}
			else if(method.equals("PUT"))
			{
				//new PutFileHandler(o, uri, parentUri).handle(t);
			}
			else if(method.equals("DELETE"))
			{
				deleteFile(o);
				WebServer.redirectChecked(t, parentUri);
			}
			else if(method.equals("OPTIONS"))
			{
				if(writable)
					sendhead.set("Allow", readWriteAllowOptions);
				else
					sendhead.set("Allow", readOnlyAllowOptions);
				try {
					t.sendResponseHeaders(204, 0);
					t.getResponseBody().close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			else
			{
				WebServer.handleErrorChecked(t, 405, new UnsupportedOperationException("Unknown or invalid HTTP method " + method));
			}
		}
		private class PostFileHandler extends HttpUploader
		{
			protected T fileObject;
			protected String uri;
			protected String parentUri;
			public PostFileHandler(T fileObject, String uri, String parentUri)
			{
				this.fileObject = fileObject;
				this.uri = uri;
				this.parentUri = parentUri;
			}
			public T theFile = null;
			public String action = null;
			public String renameTo = null;
			@Override
			public void handleFile(HttpExchange t, InputStream file, Map<String, String> attr)
					throws Exception {
				String type = attr.get("name").toLowerCase(Locale.ROOT);
				//System.out.printf("[info] [debug] [NewAbstractHttpFileServer<T>.PostFileHandler] Called handleFile() with file = \"%s\" and filename = \"%s\"\n", attr.get("name"), attr.get("filename"));
				if(type.equals("upload"))
				{
					T newfile = addSuffixToBase(fileObject, attr.get("filename"));
					OutputStream os = openOutputStream(newfile);
					file.transferTo(os);
					os.close();
				}
				else if(type.equals("file"))
				{
					theFile = addSuffixToBase(fileObject, new String(file.readAllBytes()));
					//System.out.printf("[info] [debug] [NewAbstractHttpFileServer<T>.PostFileHandler] theFile is now \"%s\"\n", theFile);
				}
				else if(type.equals("renameto"))
				{
					renameTo = new String(file.readAllBytes());
					//System.out.printf("[info] [debug] [NewAbstractHttpFileServer<T>.PostFileHandler] renameTo is now \"%s\"\n", renameTo);
				}
				else if(type.equals("create") || type.equals("delete") || type.equals("rename"))
				{
					action = type;
				}
				
					
				/*if(action.equals("upload"))
				{
					
				}
				else if(action.equals("create"))
				{
					String newfile = new String(file.readAllBytes());
					createDirectory(addSuffixToBase(fileObject, newfile));
				}
				else if(action.equals("delete"))
				{
					String newfile = new String(file.readAllBytes());
					deleteFile(addSuffixToBase(fileObject, newfile));
				}*/
			}
			@Override
			public void doHandle(HttpExchange t) {
				try {
					System.out.printf("[info] [debug] [NewAbstractHttpFileServer<T>.PostFileHandler] Completing action \"%s\" on file \"%s\" (renameTo is \"%s\")\n", action, theFile, renameTo);
					if(action != null)
					{
						if(action.equals("create"))
						{
							if(theFile != null)
								createDirectory(theFile);
							else
							{
								System.err.printf("[fail] [NewAbstractHttpFileServer<T>.PostFileHandler] Folder creation requested, but no name was specified! (theFile = null)\n");
								WebServer.handleErrorChecked(t, 400, new IllegalStateException("Folder creation requested, but no name was specified!"));
								return;
							}
						}
						else if(action.equals("delete"))
						{
							if(theFile != null)
								deleteFile(theFile);
							else
							{
								System.err.printf("[fail] [NewAbstractHttpFileServer<T>.PostFileHandler] File deletion requested, but target file was not specified! (theFile = null)\n");
								WebServer.handleErrorChecked(t, 400, new IllegalStateException("File deletion requested, but target file was not specified!"));
								return;
							}
						}
						else if(action.equals("rename"))
						{
							if(theFile != null && renameTo != null)
								renameFile(theFile, renameTo);
							else
							{
								String err = String.format("File rename requested, but source and/or new name was not specified! (src = \"%s\" renameTo = \"%s\")\n", theFile, renameTo);
								System.err.printf("[fail] [NewAbstractHttpFileServer<T>.PostFileHandler] %s)\n", err);
								WebServer.handleErrorChecked(t, 400, new IllegalStateException(err));
								return;
							}
						}
						else
						{
							String err = String.format("Unrecognized action requested (\"%s\") for file \"%s\" (renameTo = \"%s\")\n", action, theFile, renameTo);
							System.err.printf("[fail] [NewAbstractHttpFileServer<T>.PostFileHandler] %s)\n", err);
							WebServer.handleErrorChecked(t, 400, new IllegalStateException(err));
							return;
						}
					}
					else
						System.err.printf("[warn] [NewAbstractHttpFileServer<T>.PostFileHandler] action is null, so no action was performed!\n");
					HtmlPageFactory pw = printDir(fileObject, uri, parentUri, true);
					pw.sendResponse(200, t);
					pw.close();
				} catch (IOException e) {
					e.printStackTrace();
					WebServer.handleErrorChecked(t, 500, e);
				}
			}
		}
	}
	
	public static class HttpLocalFileServer extends NewAbstractHttpFileServer<File>
	{
		File f;
		public HttpLocalFileServer(File base)
		{
			f = base;
		}
		public HttpLocalFileServer(String localPath)
		{
			this(new File(localPath));
		}
		
		@Override
		public void handle(HttpExchange exchange) throws IOException {
			doHandle(exchange, 0l, 200, true);
		}

		@Override
		public File getRequestedFileFromBase(String concat) throws Exception {
			return addSuffixToBase(f, concat);
		}
		
		public File addSuffixToBase(File base, String concat) throws Exception {
			File requestedFile = new File(base.getPath(), concat);
			if(!requestedFile.getCanonicalPath().startsWith(base.getCanonicalPath()))
			{
				failcode = 403;
				throw new SecurityException("File traversal is not allowed!");
			}
			return requestedFile;
		}

		@Override
		public long getFreeSpace(File fileObject) {
			return fileObject.getFreeSpace();
		}
		@Override
		public long getTotalSpace(File fileObject) {
			return fileObject.getTotalSpace();
		}
		@Override
		public boolean isDirectory(File fileObject) {
			return fileObject.isDirectory();
		}
		public File[] getChildren(File fileObject) {
			return fileObject.listFiles();
		}
		@Override
		public long estimateSize(File fileObject) {
			return fileObject.length();
		}
		public InputStream openInputStream(File fileObject) throws IOException {
			return new BufferedInputStream(new FileInputStream(fileObject));
		}
		@Override
		public String getName(File fileObject) {
			return fileObject.getName();
		}
		@Override
		public boolean isRegularFile(File fileObject) {
			return fileObject.isFile();
		}
		@Override
		public boolean lastModifiedSupported() {
			return true;
		}
		@Override
		public Date getLastModified(File fileObject) {
			return new Date(fileObject.lastModified());
		}
		@Override
		public void deleteFile(File fileObject) {
			Helper.deleteFileAndContents(fileObject);
		}
		@Override
		public OutputStream openOutputStream(File fileObject) throws IOException {
			return new BufferedOutputStream(new FileOutputStream(fileObject));
		}
		@Override
		public void createDirectory(File fileObject) throws IOException {
			fileObject.mkdirs();
		}
		@Override
		public void renameFile(File fileObject, String newName) {
			File proposedFileName = new File(fileObject.getParentFile(), newName);
			
			// TODO some security checks lol
			//if(!proposedFileName.exists())
			if(!fileObject.renameTo(proposedFileName))
				System.err.printf("[fail] [HttpLocalFileServer] When moving \'%s\' -> \'%s\': File.renameTo() failed!\n", fileObject, proposedFileName);
		}
	}
	
	public static class HttpCompressedDirectoryServer implements HttpHandler
	{
		public Path path;
		public HttpCompressedDirectoryServer(Path theDirectory)
		{
			path = theDirectory;
		}
		public HttpCompressedDirectoryServer(File theDirectory)
		{
			this(theDirectory.toPath());
		}
		@Override
		public void handle(HttpExchange t)
		{
			try {
				t.sendResponseHeaders(200, 0);
				OutputStream os = new BufferedOutputStream(t.getResponseBody());
				ZipOutputStream zos = new ZipOutputStream(os);
				Helper.writeDirectoryToZipOutputStream(path, zos);
				zos.close();
			} catch (IOException e) {
				WebServer.handleErrorChecked(t, 500, e);
			}
		}
	}
	
	/**
	 * 
	 * @author Derek McCants
	 * @deprecated Use <code>NewAbstractHttpFileServer&lt;T&gt;</code>
	 */
	@Deprecated
	public static abstract class AbstractHttpFileServer implements HttpHandler
	{
		File f;
		int code;
		boolean writeable; // unused
		long cache;
		public void handle(HttpExchange t)
		{
			String method = t.getRequestMethod().toUpperCase(Locale.ROOT);
			//Headers header = t.getRequestHeaders();
			//InputStream is = t.getRequestBody();
			HttpContext ctx = t.getHttpContext();
			String uri = null;
			//uri = URLDecoder.decode(t.getRequestURI().normalize().toString(), StandardCharsets.UTF_8);
			//uri = t.getRequestURI().normalize().toString();
			uri = t.getRequestURI().normalize().toString();
			String cph = ctx.getPath();
			Headers sendhead = t.getResponseHeaders();
			String requestedFileSuffix = "";
			if(!uri.startsWith(cph))
				System.err.println("Wait, something happened!! uri = \"" + uri + "\" and context is \"" + cph + "\"");
			requestedFileSuffix = uri.substring(cph.length());
			File requestedFile = new File(f.getPath(), requestedFileSuffix);
			try {
				if(!requestedFile.getCanonicalPath().startsWith(f.getCanonicalPath()))
				{
					WebServer.handleErrorChecked(t, 403, new SecurityException("File traversal is not allowed!"));
					return;
				}
				if(method.equals("GET") || method.equals("HEAD"))
				{
					if(cache > 0)
						sendhead.add("Cache-Control", "max-age=" + cache);
					if(requestedFile.isDirectory())
					{
						sendhead.add("Content-Type", "text/html");
						
						if(method.equals("HEAD"))
						{
							t.sendResponseHeaders(200, -1);
							return;
						}
						HtmlPageFactory pw = new HtmlPageFactory();
						try {
							String parentUri = URLDecoder.decode(new URI(t.getRequestURI().toString() + "/..").normalize().toString(), StandardCharsets.UTF_8.name());
							parentUri = Helper.escapeHTML(parentUri);
							pw.print("<section id=\"featured\" class=\"\">");
							pw.print(	"<div class=\"cta-text\">");
							pw.print(		"<div>");
							pw.print(			"<p style=\"font-size: 36px; color:#656565;\">Directory Listing</p>");
							pw.print(			"<span style=\"margin-left: 20px;\">");
							double percentFree = 100 * (((double)requestedFile.getFreeSpace()) / requestedFile.getTotalSpace());
							if(percentFree < 5)
								pw.print("<b style=\"color: red;\">");
							pw.printf("%s free / %s total (%.2f%% free)", Helper.prettySize(requestedFile.getFreeSpace()), Helper.prettySize(requestedFile.getTotalSpace()), percentFree);
							if(percentFree < 5)
								pw.print("</b>");
							pw.print(			"</span>");
							pw.print(		"</div>");
							pw.print(	"</div>");
							pw.print("</section>");
							
							pw.print("<section id=\"content\">");
							pw.print(	"<div class=\"container\">");
							pw.print(		"<div class=\"row fadeInUpBig\">");
							pw.print(			"<div class=\"col-lg-12\">");
							pw.print(				"<div class=\"row\">");
							pw.print(					"<div class=\"col-lg-12\">");
							pw.printf(						"<p style=\"text-align:center; word-wrap: break-word;\">%s</p>", Helper.escapeHTML(uri));
							pw.print(					"</div>");
							pw.print(				"</div>");
							pw.print(				"<div class=\"row\">");
							pw.print(					"<div class=\"col-lg-12\">");
							
							pw.print(		"<table class=\"table table-hover\" style=\"font-size: small\">");
							pw.print(			"<tbody>");
							pw.print(				"<tr>");
							pw.print(					"<th valign=\"top\" style=\"white-space: nowrap; width: 32px;\"> </th>");
							pw.print(					"<th style=\"word-wrap: break-word; word-break: break-all;\">Name</th>");
							pw.print(					"<th style=\"text-align: right;\">Last Modified</th>");
							pw.print(					"<th style=\"text-align: right;\">Size</th>");
							pw.print(				"</tr>");
							pw.print(				"<tr class=\"clickable-row\" data-href=\"" + parentUri + "\" onclick=\"window.location=this.dataset.href\">");
							pw.print(					"<td valign=\"top\">");
							pw.print(						"<img src=\"/asset/icon/folder.png\" style=\"width: 24px;height: auto;\">");
							pw.print(					"</td>");
							pw.print(					"<td colspan=\"3\">");
							pw.print(						"<a href=\"" + parentUri + "\">Navigate up a directory</a>");
							pw.print(					"</td>");
							pw.print(				"</tr>");
							File[] children = requestedFile.listFiles();
							if(children == null)
							{
								pw.print("<tr><td colspan=\"4\"><i>Access was denied.</i></td></tr>");
							}
							else if(children.length == 0)
							{
								pw.print("<tr><td colspan=\"4\"><i>This directory is empty.</i></td></tr>");
							}
							else
							{
								for(File child : children)
								{
									String name = child.getName();
									String ext = "unknown";
									int dotindex;
									if((dotindex = name.lastIndexOf('.')) >= 0)
										ext = name.substring(dotindex + 1);
									String icon = child.isDirectory() ? "folder" : ext.toLowerCase();
									InputStream is;
									if((is = getClass().getResourceAsStream("/html/asset/icon/" + icon + ".png")) != null)
										is.close();
									else
										icon = "unknown";
									String newuri = uri;
									char c = uri.charAt(uri.length() - 1);
									if(c == '/' || c == '\\')
										;
									else
										newuri += "/";
									newuri += name;
									newuri = Helper.escapeHTML(newuri);
									Date d = new Date(child.lastModified());
									String sz = "";
									if(!child.isDirectory())
									{
										if(!child.isFile())
											sz = "infinity";
										else
											sz = Helper.prettySize(child.length());
									}
									pw.printf("<tr class=\"clickable-row\" data-href=\"%s\" onclick=\"window.location=this.dataset.href\">", newuri);
									pw.print(	"<td valign=\"top\">");
									pw.printf(		"<img src=\"/asset/icon/%s.png\" style=\"width: 24px;height: auto;\">", icon);
									pw.print(	"</td>");
									pw.print(	"<td style=\"word-wrap: break-word; word-break: break-all;\">");
									pw.printf(		"<b><a href=\"%s\">%s</a></b>", newuri, Helper.escapeHTML(name));
									pw.print(	"</td>");
									pw.printf(	"<td align=\"right\">%s</td>", d.toString());
									pw.printf(	"<td align=\"right\">%s</td>", sz);
									pw.print("</tr>");
								}
							}
							//pw.print("<tr><th colspan=\"4\"><hr></th></tr>");
							pw.print("</tbody></table>");
							pw.print(					"</div>");
							pw.print(				"</div>");
							pw.print(			"</div>");
							pw.print(		"</div>");
							pw.print(	"</div>");
							pw.print("</section>");
							pw.sendResponse(200, t);
							pw.close();
						} catch (IOException e) {
							e.printStackTrace();
							WebServer.handleErrorChecked(t, 500, e);
						} catch (IllegalFormatException | URISyntaxException e) {
							e.printStackTrace();
							WebServer.handleErrorChecked(t, 500, e);
						}
					}
					else
					{
						try {
							FileInputStream fis = new FileInputStream(requestedFile);
							if(method.equals("HEAD"))
							{
								t.sendResponseHeaders(code, -1);
								fis.close();
								return;
							}
							t.sendResponseHeaders(code, requestedFile.length());
							BufferedOutputStream os = new BufferedOutputStream(t.getResponseBody());
							byte[] buf = new byte[65535];
							int read;
							while((read = fis.read(buf)) > 0)
								os.write(buf, 0, read);
							fis.close();
							os.flush();
							os.close();
						} catch (FileNotFoundException e) {
							e.printStackTrace();
							WebServer.handleErrorChecked(t, 404, e);
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}
				else if((method.equals("POST") || method.equals("PUT")) && !writeable)
				{
					WebServer.handleErrorChecked(t, 405, new UnsupportedOperationException("Requested write to read-only content at " + uri));
				}
				else if((method.equals("POST") || method.equals("PUT")))
				{
					WebServer.handleErrorChecked(t, 501, new UnsupportedOperationException("Uploading is not yet supported by this API, sorry :/"));
				}
				else
				{
					WebServer.handleErrorChecked(t, 501, new UnsupportedOperationException("Uploading is not yet supported by this API, sorry :/"));
				}
			} catch (IOException e) {
				e.printStackTrace();
				WebServer.handleErrorChecked(t, 500, e);
			}
		}
	}
	
	/**
	 * 
	 * @author Derek McCants
	 * @deprecated Use <code>HttpLocalFileServer</code>
	 */
	@Deprecated
	public static class HttpFileServer extends AbstractHttpFileServer
	{
		public HttpFileServer(String path)
		{
			this(new File(path), false, 0);
		}
		public HttpFileServer(String path, long cache)
		{
			this(new File(path), false, cache);
		}
		public HttpFileServer(File file, boolean writeable, long cache)
		{
			f = file;
			this.code = 200;
			this.writeable = writeable;
			this.cache = cache;
		}
	}
	
	public static class HttpResourceServer implements HttpHandler
	{
		String path;
		int code;
		long cache;
		
		public HttpResourceServer(String path)
		{
			this.path = path;
			cache = 86400;
			code = 200;
		}
		protected void serveBody(HttpExchange t, InputStream is, int code) throws IOException
		{
			t.sendResponseHeaders(code, 0);
			is.transferTo(t.getResponseBody());
			t.getResponseBody().close();
		}
		public void handle(HttpExchange t)
		{
			String method = t.getRequestMethod().toUpperCase(Locale.ROOT);
			HttpContext ctx = t.getHttpContext();
			String uri = null;
			try {
				uri = URLDecoder.decode(t.getRequestURI().normalize().toString(), StandardCharsets.UTF_8.name());
			} catch (UnsupportedEncodingException e1) {
				e1.printStackTrace(); // This will never happen
			}
			String cph = ctx.getPath();
			Headers sendhead = t.getResponseHeaders();
			if(cache > 0)
				sendhead.add("Cache-Control", "max-age=" + cache);
			String requestedFileSuffix = "";
			if(!uri.startsWith(cph))
				System.err.println("Wait, something happened!! uri = \"" + uri + "\" and context is \"" + cph + "\"");
			requestedFileSuffix = uri.substring(cph.length());
			String requestedFile;
			if(!requestedFileSuffix.isEmpty())
				requestedFile = path + requestedFileSuffix;
			else
				requestedFile = path;
			try {
				if(method.equals("GET") || method.equals("HEAD"))
				{
					InputStream is = getClass().getResourceAsStream(requestedFile);
					if(is == null)
					{
						WebServer.handleErrorChecked(t, 404, new FileNotFoundException("Could not load " + requestedFile));
						return;
					}
					if(method.equals("HEAD"))
					{
						t.sendResponseHeaders(code, -1);
						is.close();
						t.getResponseBody().close();
						return;
					}
					serveBody(t, is, code);
				}
				else if((method.equals("POST") || method.equals("PUT")))
				{
					WebServer.handleErrorChecked(t, 405, new UnsupportedOperationException("Requested write to read-only content at " + uri));
				}
				else
				{
					WebServer.handleErrorChecked(t, 405, new UnsupportedOperationException("Unknown or invalid HTTP method " + method));
				}
			} catch (IOException e) {
				e.printStackTrace();
				WebServer.handleErrorChecked(t, 500, e);
			}
		}
	}
	public static class IOStream
	{
		public InputStream in;
		public OutputStream out;
		public IOStream(InputStream in, OutputStream out)
		{
			this.in = in;
			this.out = out;
		}
	}
	public static class WebSocketServer
	{
		public static final String SEC_WEBSOCKET_ACCEPT_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // as per RFC6455 Section 4.2.2
		public static final String calculate_Sec_WebSocket_Accept(String sec_Websocket_key)
		{
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("SHA-1");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace(); // this will never happen
			}
			return Base64.getEncoder().encodeToString(md.digest((sec_Websocket_key + SEC_WEBSOCKET_ACCEPT_MAGIC).getBytes()));
		}
		
		public WebSocketServer(HttpExchange t) throws IOException
		{
			closed = false;
			Headers h = t.getRequestHeaders();
			if(!h.containsKey("Upgrade"))
				throw new IOException("missing Upgrade header!");
			List<String> header = h.get("Upgrade");
			if(header.isEmpty() || !header.get(0).toLowerCase().contains("websocket"))
				throw new IOException("Upgrade header is not websocket!");
			if(!h.containsKey("Sec-WebSocket-Key"))
				throw new IOException("missing Sec-WebSocket-Key header!");
			System.err.printf("[info] Upgrading connection to WebSocket\n");
			String sec_websocket_key = h.get("Sec-WebSocket-Key").get(0);
			IOStream rawios = HttpExchangeHack.hackRawStreamsFromExchange(t); // yikes
			ris = new BufferedInputStream(rawios.in);
			ros = new BufferedOutputStream(rawios.out);
			PrintWriter httpRes = new PrintWriter(ros);
			httpRes.print("HTTP/1.1 101 Switching Protocols\r\n");
			httpRes.print("Upgrade: websocket\r\n");
			httpRes.print("Connection: upgrade\r\n");
			httpRes.printf("Sec-WebSocket-Accept: %s\r\n", calculate_Sec_WebSocket_Accept(sec_websocket_key));
			httpRes.print("\r\n");
			httpRes.flush();
			ios = new IOStream(new WebSocketUnpacker(), new WebSocketPacker());
		}
		private IOStream ios;
		public IOStream getIOStream()
		{
			return ios;
		}
		private InputStream ris;
		private OutputStream ros;
		private static final void pushOntoDeque(Deque<Byte> d, byte[] b)
		{
			for(int i = 0; i < b.length; ++i)
				d.addLast(b[i]);
		}
		public void sendClosePkt(byte... reason) throws IOException
		{
			if(reason == null)
			{
				ros.write(new byte[] { (byte) 0x88, 0 });
				return;
			}
			if(reason.length > 125)
				throw new IOException("reason too long!");
			byte closePkt[] = new byte[2 + reason.length];
			closePkt[0] = (byte) 0x88;
			closePkt[1] = (byte) reason.length;
			for(int i = 0; i < reason.length; ++i)
				closePkt[i + 2] = reason[i];
			ros.write(closePkt);
			ros.flush();
		}
		public void onClosed()
		{
			
		}
		public boolean closed;
		public void closeServer(byte... reason) throws IOException
		{
			if(closed)
				return;
			sendClosePkt(reason);
			ros.close();
			ris.close();
			closed = true;
			onClosed();
		}
		public void close() throws IOException
		{
			if(closed)
				return;
			ios.out.close();
			ios.in.close();
			closed = true;
			onClosed();
		}
		private static class WebSocketPacket
		{
			public boolean fin;
			public int opcode;
			public boolean mask;
			public long len;
			public byte[] maskKey;
			public byte[] decoded;
			public WebSocketPacket()
			{
				fin = false;
				mask = false;
			}
			/*public static WebSocketPacket[] splitToPackets(int mtu, boolean binary, byte[] data)
			{
				if(mtu < 1)
					throw new IllegalArgumentException("Illegal maximum packet size " + mtu);
				WebSocketPacket[] wsp = new WebSocketPacket[data.length / mtu];
			}*/
			public WebSocketPacket(InputStream in) throws IOException
			{
				this();
				read(in);
			}
			private byte assumeNext(InputStream in) throws IOException
			{
				int i = in.read();
				if(i < 0)
					throw new EOFException("Unexpected EOF");
				return (byte) i;
			}
			public void read(InputStream in) throws IOException
			{
				int byte1 = assumeNext(in);
				fin = (byte1 & 0b10000000) != 0;
				opcode = byte1 & 0x0f;
				int byte2 = assumeNext(in);
				mask = (byte2 & 0b10000000) != 0;
				len = byte2 & 0x7f;
				if(len == 126)
				{
					len = (assumeNext(in)) << 8;
					len += assumeNext(in);
				}
				else if(len == 127)
				{
					len = (assumeNext(in)) << 56;
					len += (assumeNext(in)) << 48;
					len += (assumeNext(in)) << 40;
					len += (assumeNext(in)) << 32;
					len += (assumeNext(in)) << 24;
					len += (assumeNext(in)) << 16;
					len += (assumeNext(in)) << 8;
					len += (assumeNext(in));
				}
				if(mask)
				{
					maskKey = new byte[4];
					maskKey[0] = (byte) assumeNext(in);
					maskKey[1] = (byte) assumeNext(in);
					maskKey[2] = (byte) assumeNext(in);
					maskKey[3] = (byte) assumeNext(in);
				}
				decoded = new byte[(int) len];
				if(mask)
					for(long i = 0; i < len; ++i)
						decoded[(int) i] = (byte) (assumeNext(in) ^ maskKey[(int) (i % 4)]);
				else
					for(long i = 0; i < len; ++i)
						decoded[(int) i] = assumeNext(in);
			}
			public void write(OutputStream out) throws IOException
			{
				int byte1 = opcode;
				if(fin)
					byte1 |= 0b10000000;
				else
					byte1 &= 0b01111111;
				out.write(byte1);
				if(len > 65535)
				{
					out.write(127);
					out.write((int) (len >> 56) & 0xff);
					out.write((int) (len >> 48) & 0xff);
					out.write((int) (len >> 40) & 0xff);
					out.write((int) (len >> 32) & 0xff);
					out.write((int) (len >> 24) & 0xff);
					out.write((int) (len >> 16) & 0xff);
					out.write((int) (len >> 8) & 0xff);
					out.write((int) (len) & 0xff);
				}
				else if(len > 126)
				{
					out.write(126);
					out.write((int) (len >> 8) & 0xff);
					out.write((int) (len) & 0xff);
				}
				else
					out.write((int)len);
				out.write(decoded);
			}
		}
		private class WebSocketUnpacker extends FilterInputStream
		{
			private Deque<Byte> waiting;
			private boolean closed;
			public WebSocketUnpacker()
			{
				super(ris);
				waiting = new ArrayDeque<Byte>();
				closed = false;
			}
			
			private void recvPkt() throws IOException
			{
				boolean done = false;
				while(!done)
				{
					WebSocketPacket pkt = null;
					try {
						pkt = new WebSocketPacket(ris);
					} catch (IOException e) {
						closed = true;
						return;
					}
					switch(pkt.opcode)
					{
					case 0x0:	// continuation frame
					case 0x1:	// text frame (start)
					case 0x2:	// binary frame (start)
						done = pkt.fin;
						pushOntoDeque(waiting, pkt.decoded);
						break;
					case 0x8:	// connection close
						if(!pkt.fin)
							throw new IOException("Fragmentation of control frame (close) is forbidden by RFC6455 Section 5.5");
						handleClose(pkt);
						break;
					case 0x9:	// ping
						if(!pkt.fin)
							throw new IOException("Fragmentation of control frame (ping) is forbidden by RFC6455 Section 5.5");
						handlePing(pkt);
						break;
					case 0xA:	// pong (this should never happen)
						if(!pkt.fin)
							throw new IOException("Fragmentation of control frame (pong) is forbidden by RFC6455 Section 5.5");
						// do nothing
						break;
					default:
						throw new IOException(String.format("unknown opcode %x", pkt.opcode));
					}
				}
				/*System.err.printf("[info] Accepted connection, waiting for first data...\n");
				byte buffer[] = new byte[8192];
				int len = ris.read(buffer);
				System.out.printf("read %d bytes from websocket\n", len);*/
			}
			private void handleClose(WebSocketPacket pkt) throws IOException
			{
				closeServer(pkt.decoded);
			}
			public void close() throws IOException
			{
				closeServer((byte)0x03,(byte)0xe8);
			}
			private void handlePing(WebSocketPacket pkt) throws IOException
			{
				if(!pkt.fin)
					throw new IOException("Fragmentation of control frame (Connection close) is forbidden by RFC6455 Section 5.5");
				pkt.opcode = 0xA;
				pkt.write(ros);
				ros.flush();
			}
			@Override
			public int read(byte[] b, int off, int len) throws IOException
			{
				//System.err.printf("entered read(byte[], %d, %d)\n", off, len);
				if(closed)
					return -1;
				if(waiting.isEmpty())
					recvPkt();
				//System.err.printf("back from recvPkt()\n");
				int i = off;
				for(; i < len; ++i)
				{
					if(waiting.isEmpty())
						break;
					b[i] = waiting.pop();
				}
				//System.err.printf("in read(byte[], %d, %d): read %d bytes\n", off, len, i - off);
				return i - off;
			}
			@Override
			public int read(byte[] b) throws IOException
			{
				return read(b, 0, b.length);
			}
			@Override
			public int read() throws IOException
			{
				if(closed)
					return -1;
				if(waiting.isEmpty())
					recvPkt();
				//System.err.printf("in read(), returning last byte\n");
				return waiting.pop();
			}
		}
		private class WebSocketPacker extends FilterOutputStream
		{
			public boolean binary;
			public WebSocketPacker()
			{
				super(ros);
			}
			@Override
			public void write(byte[] c, int off, int len) throws IOException
			{
				int byte1 = (binary ? 0x2 : 0x1) | 0b10000000;
				out.write(byte1);
				if(len > 65535)
				{
					out.write(127);
					out.write((int) (len >> 56) & 0xff);
					out.write((int) (len >> 48) & 0xff);
					out.write((int) (len >> 40) & 0xff);
					out.write((int) (len >> 32) & 0xff);
					out.write((int) (len >> 24) & 0xff);
					out.write((int) (len >> 16) & 0xff);
					out.write((int) (len >> 8) & 0xff);
					out.write((int) (len) & 0xff);
				}
				else if(len > 126)
				{
					out.write(126);
					out.write((int) (len >> 8) & 0xff);
					out.write((int) (len) & 0xff);
				}
				else
					out.write((int)len);
				out.write(c, off, len);
				out.flush();
			}
			@Override
			public void write(byte[] c) throws IOException
			{
				write(c, 0, c.length);
			}
			@Override
			public void write(int c) throws IOException
			{
				write(new byte[] {(byte)c});
			}
			
			@Override
			public void close() throws IOException
			{
				closeServer((byte)0x03,(byte)0xe8);
			}
		}
	}
	
	public abstract static class HttpTtyServer implements HttpHandler
	{
		public abstract IOStream openTty(HttpExchange t) throws IOException;
		public abstract void closeTty() throws IOException;
		public abstract void waitForExternalToClose();
		public abstract void handlePreHandshake(HttpExchange t) throws IOException;
		private volatile boolean running;
		private volatile boolean closed;
		//public static final Runnable read_from_web_runnable = new Runnable() {};
		@Override
		public void handle(HttpExchange t) throws IOException
		{
			Headers h = t.getRequestHeaders();
			if(!h.containsKey("Upgrade"))
			{
				handlePreHandshake(t);
				return;
			}
			List<String> header = h.get("Upgrade");
			if(header.isEmpty() || !header.get(0).toLowerCase().contains("websocket"))
			{
				handlePreHandshake(t);
				return;
			}
			if(!h.containsKey("Sec-WebSocket-Key"))
			{
				handlePreHandshake(t);
				return;
			}
			System.out.printf("[info] Upgrading connection to WebSocket\n");
			WebSocketServer srv = new WebSocketServer(t);
			IOStream tty;
			try {
				tty = openTty(t);
			} catch (Exception e) {
				srv.getIOStream().out.write(e.toString().getBytes());
				srv.closeServer((byte)0x03,(byte)0xe8);
				return;
			}
			running = true;
			closed = false;
			Thread read_from_web = new Thread() {
				public void run()
				{
					byte[] buffer = new byte[8192];
					int len;
					try {
						while(running)
						{
							len = srv.getIOStream().in.read(buffer);
							//System.err.printf("sending %d bytes to process\n", len);
							if(len <= 0)
								break;
							tty.out.write(buffer, 0, len);
							tty.out.flush();
						}
					} catch (IOException e) {
						e.printStackTrace();
					} finally {
						try {
							srv.closeServer();
						} catch (IOException e) {
							e.printStackTrace();
						}
						try {
							closeTty();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
					System.err.println("[info] DEBUG -> read_from_web is exiting");
				}
			};
			Thread read_from_proc = new Thread() {
				public void run()
				{
					byte[] buffer = new byte[8192];
					int len;
					try {
						while(running)
						{
							//System.err.printf("waiting for external process...");
							len = tty.in.read(buffer);
							//System.err.printf("got %d bytes from external process\n", len);
							//for(int tmp = 0; tmp < len; ++tmp)
							//	System.err.printf("%c", buffer[tmp]);
							//System.err.println();
							if(len <= 0)
								break;
							srv.getIOStream().out.write(buffer, 0, len);
						}
					} catch (IOException e) {
						e.printStackTrace();
					} finally {
						try {
							srv.closeServer((byte)0x03,(byte)0xe8);
							closed = true;
						} catch (IOException e) {
							e.printStackTrace();
						}
						try {
							closeTty();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
					System.err.println("[info] DEBUG -> read_from_proc is exiting");
				}
			};
			read_from_web.start();
			read_from_proc.start();
			waitForExternalToClose();
			running = false;
			try {
				if(!closed)
					srv.closeServer((byte)0x03,(byte)0xe8);
			} catch (IOException e) {
				e.printStackTrace();
			}
			try {
				closeTty();
			} catch (IOException e) {
				e.printStackTrace();
			}
			System.err.println("[info] Exited from main thread");
			
		}
	}
	
	public abstract static class HttpShellServer extends HttpTtyServer
	{
		public static final HtmlPageFactory static_get = new HtmlPageFactory();
		public static String getExampleCommand()
		{
			return null;
		}
		static
		{
			static_get.print("<script>");
			static_get.print(	"function load_stage2() {");
			static_get.print(		"tty = document.getElementById(\"tty\");");
			static_get.print(		"tty.innerHTML = '';");
			static_get.print(		"cmd = document.getElementById(\"cmd\");");
			static_get.print(		"cmd.disabled = false;");
			static_get.print(		"btn = document.getElementById(\"run\");");
			static_get.print(		"btn.disabled = false;");
			static_get.print(		"echo = document.getElementById(\"echo\");");
			static_get.print(		"proto = window.location.protocol.toLowerCase().startsWith(\"https\") ? \"wss://\" : \"ws://\";");
			static_get.print(		"ws = new WebSocket(proto + window.location.host + window.location.pathname);");
			static_get.print(		"ws.onmessage = function(f) { tty.append(f.data); window.scrollTo(0, document.body.scrollHeight); };");
			static_get.print(		"ws.onclose = function(f) { cmd.disabled = true; btn.disabled = true; };");
			static_get.print(		"btn.onclick = function(f) {");
			static_get.print(			"ws.send(cmd.value + \"\\n\");");
			static_get.print(			"if(echo.checked) {");
			static_get.print(				"tty.append(cmd.value + \"\\n\");");
			static_get.print(			"}");
			static_get.print(			"cmd.value = '';");
			static_get.print(			"return false;");
			static_get.print(		"};");
			static_get.print(	"}");
			static_get.print("</script>");
			static_get.createTitle("Shell");
			static_get.startMainBody();
			static_get.print("<div class=\"col-lg-12\">");
			static_get.print(	"<div>");
			static_get.print(		"<input type=\"checkbox\" id=\"echo\" name=\"echo\" checked>");
			static_get.print(		"<label for=\"echo\">Echo input -&gt; output</label>");
			static_get.print(	"</div>");
			static_get.print(	"<pre id=\"tty\">JavaScript is required for this feature, but is disabled.  Enable JavaScript in your browser.");
			static_get.print(	"</pre>");
			static_get.print(	"<span>");
			static_get.print(		"<form>");
			String example = getExampleCommand();
			if(example == null)
				static_get.print(		"<input id=\"cmd\" name=\"cmd\" style=\"width:90%\" disabled>");
			else
				static_get.printf(		"<input id=\"cmd\" name=\"cmd\" placeholder=\"%s\" style=\"width:90%\" disabled>", example);
			static_get.print(			"<input id=\"run\" type=\"submit\" class=\"btn-lg btn-theme animated\" style=\"float:right;\" value=\"Run\" disabled>");
			static_get.print(		"</form>");
			static_get.print(	"</span>");
			static_get.print("</div>");
			static_get.closeAllElements();
		}
		
		@Override
		public void handlePreHandshake(HttpExchange t) throws IOException
		{
			static_get.sendResponse(200, t);
		}
	}
	
	public static class HttpCmdShellServer extends HttpShellServer
	{
		protected Process theProcess;
		protected ProcessBuilder pb;
		protected InputStream stdin;
		protected OutputStream stdout;
		public HttpCmdShellServer(ProcessBuilder builder)
		{
			pb = builder;
		}
		@Override
		public IOStream openTty(HttpExchange t) throws IOException
		{
			pb.redirectErrorStream(true);
			theProcess = pb.start();
			stdin = theProcess.getInputStream();
			stdout = theProcess.getOutputStream();
			return new IOStream(stdin, stdout);
		}
		@Override
		public void closeTty() throws IOException
		{
			theProcess.destroyForcibly();
			try {
				stdin.close();
			} catch (IOException e) {}
			try {
				stdout.close();
			} catch (IOException e) {}
		}
		@Override
		public void waitForExternalToClose()
		{
			while(theProcess.isAlive())
				try {
					theProcess.waitFor();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
	}
	
	/**
	 * 
	 * @author Derek McCants
	 * @deprecated Use <code>HttpCmdShellServer</code>
	 */
	@Deprecated
	public static class HttpToShellServer implements HttpHandler
	{
		public static final HtmlPageFactory static_get = createStaticGet();
		private static final HtmlPageFactory createStaticGet()
		{
			HtmlPageFactory pw = createHeader();
			pw.print(Helper.escapeHTML(OS_Specific.whoami));
			pw.print("@");
			pw.print(Helper.escapeHTML(OS_Specific.hostname));
			pw.print(" (");
			pw.print(Helper.escapeHTML(OS_Specific.OS));
			pw.print(")$ ");
			pw.print("Please type a command");
			pw.print("<br/>");
			return finalizeHtml(pw);
		}
		private static final HtmlPageFactory createHeader()
		{
			HtmlPageFactory hpf = new HtmlPageFactory();
			hpf.createTitle("Shell Command");
			hpf.startMainBody();
			hpf.print("<div class=\"col-lg-12\">");
			hpf.print(	"<pre>");
			return hpf;
		}
		private static final HtmlPageFactory finalizeHtml(HtmlPageFactory hpf)
		{
			hpf.print(	"</pre>");
			hpf.print(	"<form>");
			hpf.print(		"<span>");
			hpf.print(			"<input name=\"cmd\" style=\"width:90%\">");
			hpf.print(			"<input type=\"submit\" class=\"btn-lg btn-theme animated\" style=\"float:right;\" value=\"Run\">");
			hpf.print(		"</span>");
			hpf.print(	"</form>");
			hpf.print("</div>");
			hpf.closeAllElements();
			return hpf;
		}
		@Override
		public void handle(HttpExchange exchange) throws IOException
		{
			String q = exchange.getRequestURI().getQuery();
			if(q == null)
				static_get.sendResponse(200, exchange);
			else
			{
				HtmlPageFactory pw = createHeader();
				if(!q.startsWith("cmd="))
				{
					WebServer.handleErrorChecked(exchange, 400, new IllegalArgumentException("Invalid query, must start with \"cmd=\""));
					return;
				}
				String cmd = URLDecoder.decode(q.substring(4), StandardCharsets.UTF_8);
				pw.print(Helper.escapeHTML(OS_Specific.whoami));
				pw.print("@");
				pw.print(Helper.escapeHTML(OS_Specific.hostname));
				pw.print(" (");
				pw.print(Helper.escapeHTML(OS_Specific.OS));
				pw.print(")$ ");
				pw.print(Helper.escapeHTML(cmd));
				pw.print("<br/>");
				ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));
				pb.redirectErrorStream(true);
				try {
					Process p = pb.start();
					new HtmlEscapedInputStream(p.getInputStream()).transferTo(pw);
					pw.printf("<br/>The command completed with exit code %d.<br/>", p.waitFor());
				} catch (IOException e) {
					pw.print("<br/>The command could not be completed.<br/>");
					pw.print(e);
				} catch (InterruptedException e) {
					pw.print("<br/>The command could not be completed.<br/>");
					pw.print(e);
				}
				finalizeHtml(pw).sendResponse(200, exchange);
			}
		}
	}
	
	public static class HttpHtmlResourceServer extends HttpResourceServer
	{
		public HttpHtmlResourceServer(String path)
		{
			super(path);
		}
		@Override
		protected void serveBody(HttpExchange t, InputStream is, int code) throws IOException
		{
			HtmlPageFactory hpf = new HtmlPageFactory();
			is.transferTo(hpf);
			is.close();
			hpf.sendResponse(code, t);
			hpf.close();
		}
	}
	
	public static final Map<Integer, String> errmsg = new HashMap<Integer, String>();
	static
	{
		// 1xx Informational Response
		errmsg.put(100, "Continue");						// Section 6.2.1 of [RFC7231]
		errmsg.put(101, "Switching Protocols");				// Section 6.2.2 of [RFC7231]
		errmsg.put(102, "Processing");						// RFC 2518
		errmsg.put(103, "Early Hints");						// RFC 8297
		errmsg.put(110, "Response is Stale");				// Section 5.5.1 of [RFC7234]
		errmsg.put(111, "Revalidation Failed");				// Section 5.5.2 of [RFC7234]
		errmsg.put(112, "Disconnected Operation");			// Section 5.5.3 of [RFC7234]
		errmsg.put(113, "Heuristic Expiration");			// Section 5.5.4 of [RFC7234]
		errmsg.put(199, "Miscellaneous Warning");			// Section 5.5.5 of [RFC7234]
		// 2xx Success
		errmsg.put(200, "OK");								// Section 6.3.1 of [RFC7231]
		errmsg.put(201, "Created");							// Section 6.3.2 of [RFC7231]
		errmsg.put(202, "Accepted");						// Section 6.3.3 of [RFC7231]
		errmsg.put(203, "Non-Authoritative Information");	// Section 6.3.4 of [RFC7231]
		errmsg.put(204, "No Content");						// Section 6.3.5 of [RFC7231]
		errmsg.put(205, "Reset Content");					// Section 6.3.6 of [RFC7231]
		errmsg.put(206, "Partial Content");					// Section 4.1 of [RFC7233]
		errmsg.put(207, "Multi-Status");					// Section 11.1 of [RFC4918]
		errmsg.put(208, "Already Reported");				// RFC 5842
		errmsg.put(214, "Transformation Applied");			// Section 5.5.6 of [RFC7234]
		errmsg.put(226, "IM Used");							// RFC 3229
		errmsg.put(299, "Miscellaneous Persistent Warning");// Section 5.5.7 of [RFC7234]
		// 3xx Redirection
		errmsg.put(300, "Multiple Choices");				// Section 6.4.1 of [RFC7231]
		errmsg.put(301, "Moved Permanently");				// Section 6.4.2 of [RFC7231]
		errmsg.put(302, "Found");							// Section 6.4.3 of [RFC7231]
		errmsg.put(303, "See Other");						// Section 6.4.4 of [RFC7231]
		errmsg.put(304, "Not Modified");					// Section 4.1 of [RFC7232]
		errmsg.put(305, "Use Proxy");						// Section 6.4.5 of [RFC7231]
		errmsg.put(306, "Switch Proxy");					// RFC 2616
		errmsg.put(307, "Temporary Redirect");				// Section 6.4.7 of [RFC7231]
		errmsg.put(308, "Permanent Redirect");				// Section 3 of [RFC7538]
		// 4xx Client Error
		errmsg.put(400, "Bad Request");						// Section 6.5.1 of [RFC7231]
		errmsg.put(401, "Unauthorized");					// Section 3.1 of [RFC7235]
		errmsg.put(402, "Payment Required");				// Section 6.5.2 of [RFC7231]
		errmsg.put(403, "Forbidden");						// Section 6.5.3 of [RFC7231]
		errmsg.put(404, "Not Found");						// Section 6.5.4 of [RFC7231]
		errmsg.put(405, "Method Not Allowed");				// Section 6.5.5 of [RFC7231]
		errmsg.put(406, "Not Acceptable");					// Section 6.5.6 of [RFC7231]
		errmsg.put(407, "Proxy Authentication Required");	// Section 3.2 of [RFC7235]
		errmsg.put(408, "Request Timeout");					// Section 6.5.7 of [RFC7231]
		errmsg.put(409, "Conflict");						// Section 6.5.8 of [RFC7231]
		errmsg.put(410, "Gone");							// Section 6.5.9 of [RFC7231]
		errmsg.put(411, "Length Required");					// Section 6.5.10 of [RFC7231]
		errmsg.put(412, "Precondition Failed");				// Section 4.2 of [RFC7232]
		errmsg.put(413, "Payload Too Large");				// Section 6.5.11 of [RFC7231]
		errmsg.put(414, "URI Too Long");					// Section 6.5.12 of [RFC7231]
		errmsg.put(415, "Unsupported Media Type");			// Section 6.5.13 of [RFC7231]
		errmsg.put(416, "Range Not Satisfiable");			// Section 4.4 of [RFC7233]
		errmsg.put(417, "Expectation Failed");				// Section 6.5.14 of [RFC7231]
		errmsg.put(418, "I'm a teapot");					// Section 2.3.3 of [RFC7168]
		errmsg.put(421, "Misdirected Request");				// Section 9.1.2 of [RFC7540]
		errmsg.put(422, "Unprocessable Entity");			// Section 11.2 of [RFC4918]
		errmsg.put(423, "Locked");							// Section 11.3 of [RFC4918]
		errmsg.put(424, "Failed Dependency");				// Section 11.4 of [RFC4918]
		errmsg.put(425, "Too Early");						// RFC 8470
		errmsg.put(426, "Upgrade Required");				// Section 6.5.15 of [RFC7231]
		errmsg.put(428, "Precondition Required");			// Section 3 of [RFC6585]
		errmsg.put(429, "Too Many Requests");				// Section 4 of [RFC6585]
		errmsg.put(431, "Request Header Fields Too Large");	// Section 5 of [RFC6585]
		errmsg.put(451, "Unavailable For Legal Reasons");	// Section 3 of [RFC7725]
		// 5xx Server Error
		errmsg.put(500, "Internal Server Error");			// Section 6.6.1 of [RFC7231]
		errmsg.put(501, "Not Implemented");					// Section 6.6.2 of [RFC7231]
		errmsg.put(502, "Bad Gateway");						// Section 6.6.3 of [RFC7231]
		errmsg.put(503, "Service Unavailable");				// Section 6.6.4 of [RFC7231]
		errmsg.put(504, "Gateway Timeout");					// Section 6.6.5 of [RFC7231]
		errmsg.put(505, "HTTP Version Not Supported");		// Section 6.6.6 of [RFC7231]
		errmsg.put(506, "Variant Also Negotiates");			// RFC 2295
		errmsg.put(507, "Insuffcient Storage");				// Section 11.5 of [RFC4918]
		errmsg.put(508, "Loop Detected");					// RFC 5842
		errmsg.put(510, "Not Extended");					// RFC 2774
		errmsg.put(511, "Network Authentication Required");	// Section 6 of [RFC6585]
	}
}
