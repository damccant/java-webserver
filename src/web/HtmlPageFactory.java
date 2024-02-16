package web;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import util.SedInputStream;
import util.SerializableByteArrayOutputStream;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * This class creates a HTML page and implements some convenience methods to
 * programmatically build a dynamically generated HTML page
 * @author dmccants
 */
public class HtmlPageFactory extends OutputStream implements Serializable
{
	/**
	 * Appease the serialization gods.
	 */
	private static final long serialVersionUID = -5470874035226155125L;
	
	public static final byte[] readStaticByteArrayResource(String resource, String defaultValue)
	{
		InputStream is = null;
		try {
			is = WebServer.class.getResourceAsStream(resource);
			if(is == null)
				throw new IOException(String.format("Resource \"%s\" does not exist!", resource));
			return is.readAllBytes();
		} catch (IOException e) {
			System.err.printf("[fail] During early initialization, failed to load static resource \"%s\"\n", resource);
			e.printStackTrace();
			return defaultValue.getBytes();
		} finally {
			try {
				if(is != null)
					is.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	private static String[] alert_text, alert_type;
	private static byte[] dyn_header, dyn_footer, dyn_title;
	static
	{
		dyn_header = readStaticByteArrayResource("/html/dynamic/head.html", "<!DOCTYPE html><html><head></head><body>");
		dyn_footer = readStaticByteArrayResource("/html/dynamic/foot.html", "</body></html>");
		dyn_title = readStaticByteArrayResource("/html/dynamic/title.html", "<h1>$TEXT_TITLE_ELEMENT$</h1>");
		/*InputStream is;
		try {
			//dyn_header = Files.readAllBytes(FileSystems.getDefault().getPath("html", "dynamic_head.html"));
			is = WebServer.class.getResourceAsStream("/html/dynamic/head.html");
			if(is == null)
				throw new IOException("Resource /html/dynamic/head.html does not exist!");
			dyn_header = is.readAllBytes();
			is.close();
			//dyn_footer = Files.readAllBytes(FileSystems.getDefault().getPath("html", "dynamic_foot.html"));
			is = WebServer.class.getResourceAsStream("/html/dynamic/foot.html");
			if(is == null)
				throw new IOException("Resource /html/dynamic/foot.html does not exist!");
			dyn_footer = is.readAllBytes();
			is.close();
		} catch (IOException e) {
			System.err.println("Failed to load html/dynamic/head.html and html/dynamic/foot.html!");
			e.printStackTrace();
			dyn_header = "<!DOCTYPE html><html><head></head><body>".getBytes();
			dyn_footer = "</body></html>".getBytes();
		}
		try {
			is = WebServer.class.getResourceAsStream("/html/dynamic/title.html");
			if(is == null)
				throw new IOException("Resource /html/dynamic/title.html does not exist!");
			dyn_title = is.readAllBytes();
			is.close();
		} catch (IOException e) {
			System.err.println("Failed to load html/dynamic/title.html!");
			e.printStackTrace();
			dyn_title = "<h1>$TEXT_TITLE_ELEMENT$</h1>".getBytes();
		}*/
		InputStream is = null;
		try {
			is = WebServer.class.getResourceAsStream("/html/dynamic/alert.cfg");
			if(is == null)
				throw new IOException("Resource /html/dynamic/alert.cfg does not exist!");
			BufferedReader isr = new BufferedReader(new InputStreamReader(is));
			List<String> alert_types = new ArrayList<String>();
			List<String> alert_texts = new ArrayList<String>();
			String thisline;
			while((thisline = isr.readLine()) != null)
			{
				int space = thisline.indexOf('\t');
				if(space < 0)
					continue;
				alert_types.add(thisline.substring(0, space));
				alert_texts.add(thisline.substring(space + 1));
			}
			alert_type = new String[alert_types.size()];
			alert_text = new String[alert_texts.size()];
			alert_type = alert_types.toArray(alert_type);
			alert_text = alert_texts.toArray(alert_text);
			//for(int q = 0; q < alert_type.length; q++)
			//	System.out.printf("alert[%d] = \"%s\", \"%s\"\n", q, alert_type[q], alert_text[q]);
		} catch (IOException e) {
			System.err.println("Failed to load html/dynamic/alert.cfg");
			e.printStackTrace();
			alert_type = new String[0];
			alert_text = new String[0];
		} finally {
			try {
				if(is != null)
					is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	/*public class HttpElement
	{
		public String elem;
		public Map<String, String> attrib;
		public List<HttpElement> innerContent;
		@Override
		public String toString()
		{
			StringBuilder sb = new StringBuilder();
			sb.append("<");
			sb.append(elem);
			attrib.forEach((name, value) -> {
				sb.append(String.format(" %s=\"%s\"", name, value));
			});
			sb.append(">");
			innerContent.forEach((content) -> sb.append(content));
			sb.append(String.format("</%s>", elem));
			return sb.toString();
		}
	}*/
	private SerializableByteArrayOutputStream baos;
	private transient PrintWriter pw;
	
	private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException
	{
		ois.defaultReadObject();
		pw = new PrintWriter(baos);
	}
	
	private void writeObject(ObjectOutputStream oos) throws IOException
	{
		pw.flush();
		pw.close();
		oos.defaultWriteObject();
	}
	
	public HtmlPageFactory()
	{
		baos = new SerializableByteArrayOutputStream();
		elems = new Stack<String>();
	}
	
	private PrintWriter getPw()
	{
		return pw == null ? pw = new PrintWriter(baos) : pw;
	}
	
	public void createTitle(String text)
	{
		if(pw != null)
			pw.flush();
		try {
			(new SedInputStream(new ByteArrayInputStream(dyn_title))).replaceAll("$TEXT_TITLE_ELEMENT$", text).transferTo(baos);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void createAlert(int statusCode)
	{
		createAlert(statusCode, alert_text[statusCode]);
	}
	
	public void createAlert(int statusCode, String customMsg)
	{
		getPw().printf("<div class=\"alert %s\" role=\"alert\">%s</div>", alert_type[statusCode], customMsg);
	}
	
	public void startMainBody()
	{
		createElement("section", Map.of("id", "content"));
		createElement("div", Map.of("class", "container"));
		createElement("div", Map.of("class", "row fadeInUpBig"));
	}
	
	private Stack<String> elems;
	/**
	 * Creates the specified HTML element with the specified attributes and
	 * adds it to this HTML page
	 * @param elem The element to create, such as <code>div</code>
	 * @param attrib A map of attributes to their values
	 */
	public void createElement(String elem, Map<String, String> attrib)
	{
		elems.push(elem);
		getPw().printf("<%s", elem);
		attrib.forEach((name, value) -> getPw().printf(" %s=\"%s\"", name, value));
		getPw().print(">");
	}
	
	/**
	 * Creates the specified HTML element and
	 * adds it to this HTML page
	 * @param elem The element to create, such as <code>div</code>
	 * @param attrib A map of attributes to their values
	 */
	public void createElement(String elem)
	{
		elems.push(elem);
		getPw().printf("<%s>", elem);
	}
	
	public String closeElement() throws IllegalStateException
	{
		if(elems.isEmpty())
			throw new IllegalStateException("Trying to close an element, but one hasn't been opened!");
		String s = elems.pop();
		getPw().printf("</%s>", s);
		return s;
	}
	
	public void closeAllElements()
	{
		while(!elems.isEmpty())
			closeElement();
	}

	public long size()
	{
		if(pw != null)
			pw.flush();
		return dyn_header.length + baos.size() + dyn_footer.length;
	}
	
	public void print(String s)
	{
		getPw().print(s);
	}
	
	public void printf(String format, Object...objects)
	{
		getPw().printf(format, objects);
	}
	
	public void println(String s)
	{
		getPw().print(s);
	}
	
	public void print(Exception e)
	{
		e.printStackTrace(getPw());
	}
	
	public void writeToOutput(OutputStream os) throws IOException
	{
		if(pw != null)
			pw.flush();
		os.write(dyn_header);
		baos.transferTo(os);
		os.write(dyn_footer);
	}
	
	public void sendResponse(int code, HttpExchange exchange) throws IOException
	{
		exchange.getResponseHeaders().add("Content-Type", "text/html");
		exchange.sendResponseHeaders(200, size());
		writeToOutput(exchange.getResponseBody());
		exchange.close();
		close();
	}
	
	public boolean sendResponseChecked(int code, HttpExchange exchange)
	{
		try {
			sendResponse(200, exchange);
			return true;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	@Override
	public void close() throws IOException
	{
		baos.close();
	}

	@Override
	public void write(int b) throws IOException
	{
		if(pw != null)
			pw.flush();
		baos.write(b);
	}
	
	@Override
	public void write(byte[] b, int off, int len) throws IOException
	{
		if(pw != null)
			pw.flush();
		baos.write(b, off, len);
	}
	
	public class HtmlPageFactorySender implements HttpHandler
	{
		public void handle(HttpExchange exchange) throws IOException
		{
			sendResponse(200, exchange);
		}
	}
}
