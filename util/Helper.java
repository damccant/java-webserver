package util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

/**
 * A class containing several helper methods.  The helper methods are declared
 * static, so it is not necessary to instantiate this class.
 * @author dmccants
 */
public final class Helper
{
	private static final String base64AlphabetChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_";
	/**
	 * Returns a random String, composed of characters from the base64 alphabet
	 * <p>
	 * <b>NOTE:</b> This method is not suitable for cryptographic use
	 * @param nochars The length of the string to generate.  Returns an empty
	 * string if this is less than or equal to 0
	 * @return A new, randomly generated String
	 */
	public static final String randomBase64(int nochars)
	{
		StringBuilder q = new StringBuilder();
		for(int i = 0; i < nochars; i++)
			q.append(base64AlphabetChars.charAt(ThreadLocalRandom.current().nextInt(base64AlphabetChars.length())));
		return q.toString();
	}
	
	/**
	 * A small simple helper method to increment the minor version number of
	 * the project file.
	 * <p>
	 * For example, if given "1.3.0", this method returns "1.3.1", or if given
	 * "1.4.6.99", this method returns "1.4.6.100"
	 * @param currentVersion The version number to increment
	 * @return The incremented version number
	 */
	public static final String nextVersionOf(String currentVersion)
	{
		String[] tok = currentVersion.split("\\.");
		try {
			long newminor = Long.parseLong(tok[tok.length - 1]);
			tok[tok.length - 1] = String.valueOf(newminor + 1);
		} catch (NumberFormatException e) {
			e.printStackTrace();
			tok[tok.length - 1] += ".0";
		}
		StringBuilder sb = new StringBuilder();
		sb.append(tok[0]);
		for(int i = 1; i < tok.length; i++)
		{
			sb.append('.');
			sb.append(tok[i]);
		}
		return sb.toString();
	}
	
	public static final String prettySize(long size)
	{
		if(size == Long.MAX_VALUE)
			return "infinity";
		/*else if(size >= 1208925819614629174706176l) // this is bigger than Long.MAX_VALUE!
			sz = String.format("%.2f YB", ((double)size) / 1208925819614629174706176l);
		else if(size >= 1180591620717411303424l) // this is bigger than Long.MAX_VALUE!
			sz = String.format("%.2f ZB", ((double)size) / 1180591620717411303424l);*/
		else if(size >= 1152921504606846976l)
			return String.format("%.2f EB", ((double)size) / 1152921504606846976l);
		else if(size >= 1125899906842624l)
			return String.format("%.2f PB", ((double)size) / 1125899906842624l);
		else if(size >= 1099511627776l)
			return String.format("%.2f TB", ((double)size) / 1099511627776l);
		else if(size >= 1073741824l)
			return String.format("%.2f GB", ((double)size) / 1073741824l);
		else if(size >= 1048576l)
			return String.format("%.2f MB", ((double)size) / 1048576l);
		else if(size >= 1024l)
			return String.format("%.2f KB", ((double)size) / 1024l);
		else
			return String.format("%d B", size);
	}
	
	public static final String escapeHTML(String str)
	{
		return str.codePoints().mapToObj(c -> c > 127 || "/\"'<>&".indexOf(c) != -1 ?
				"&#" + c + ";" : new String(Character.toChars(c))).collect(Collectors.joining());
	}
	
	public static final String urlDecode(String str)
	{
		return URLDecoder.decode(str, StandardCharsets.UTF_8);
	}
	
	public static final String urlEncode(String str)
	{
		return URLEncoder.encode(str, StandardCharsets.UTF_8);
	}
	
	public static final String urlEncodeExceptSlash(String str)
	{
		String[] components = str.split("/");
		if(components.length == 0)
			return urlEncode(str); // TODO: make sure this is even correct lmao
		StringBuilder sb = new StringBuilder();
		
		for(int i = 0; i < components.length - 1; i++)
		{
			sb.append(urlEncode(components[i]));
			sb.append("/");
		}
		sb.append(urlEncode(components[components.length - 1]));
		return sb.toString();
	}
	
	public static final boolean deleteFileAndContents(File f)
	{
		if(f == null)
			return true;
		if(f.isDirectory())
		{
			File[] a = f.listFiles();
			if(a != null)
				for(File g : a)
					deleteFileAndContents(g);
			return f.delete();
		}
		return f.delete();
	}
	
	public static byte[] hexStringToByteArray(String s)
	{
		int len = s.length();
		if(len % 2 != 0)
			throw new IllegalArgumentException("Hex string does not contain an even number of digits!");
		byte[] d = new byte[len/2];
		int low, high;
		for(int i = 0; i < len; i += 2)
		{
			if((high = Character.digit(s.charAt(i), 16)) < 0)
				throw new IllegalArgumentException("Hex string contains invalid character \'" + s.charAt(i) + "\'");
			if((low = Character.digit(s.charAt(i + 1), 16)) < 0)
				throw new IllegalArgumentException("Hex string contains invalid character \'" + s.charAt(i + 1) + "\'");
			d[i/2] = (byte) ((high << 4) | low);
		}
		return d;
	}
	
	/**
	 * Finds an object contained within the array, and returns the index of
	 * its first occurrence within the array.  If the array does not contain
	 * the specified element, then -1 is returned.
	 * <p>
	 * That is to say, the lowest number <code>n</code> is returned such that
	 * <code>haystack[n] == needle || haystack[q].equals(needle)</code>.  If
	 * this is not true for any element in the <code>haystack</code> array,
	 * then -1 is returned
	 * @param <T> The type of the array and element to find
	 * @param haystack The array to search
	 * @param needle The object to find within the array
	 * @return The index of the first occurrence of <code>needle</code> within
	 * the haystack, or -1 if it is not found
	 */
	public static final <T>int find(T[] haystack, T needle)
	{
		if(haystack == null)
			return -1;
		for(int q = 0; q < haystack.length; q++)
			if(haystack[q] == needle || haystack[q].equals(needle))
				return q;
		return -1;
	}
	
	public static final <T>boolean allMatch(T[] items, Predicate<T> which, boolean defaultValue)
	{
		if(items == null || items.length <= 0)
			return defaultValue;
		for(int q = 0; q < items.length; q++)
			if(!which.test(items[q]))
				return false;
		return true;
	}
	
	public static final <T>boolean anyMatch(T[] items, Predicate<T> which, boolean defaultValue)
	{
		if(items == null || items.length <= 0)
			return defaultValue;
		for(int q = 0; q < items.length; q++)
			if(which.test(items[q]))
				return true;
		return false;
	}
	
	public static final String[] binaryFileExtensions = new String[] {
			".zip",
			".tar",
			".gz",
			".tgz",
			".7z",
			".apk",
			".jar",
			".cpio",
			".dat",
			".exe",
			".img",
			".iso",
			".fnt",
			".png",
			".mp3",
			".mp4",
			".ogg",
			".wav",
			".deb",
			".doc",
			".docx",
			".ppt",
			".pptx",
			".xls",
			".xlsx",
			".jpg",
			".jpeg",
	};
	
	public static final boolean guessIfBinaryFileFromName(String path)
	{
		String p = path.toLowerCase().trim();
		return anyMatch(binaryFileExtensions, (e) -> p.endsWith(e), false);
	}
	
	public static final boolean guessIfBinaryFile(Path path)
	{
		// TODO
		return guessIfBinaryFileFromName(path.toString());
	}
	
	public static final Map<String, String> parseQuery(URI uri)
	{
		String theQuery = uri.getRawQuery();
		if(theQuery == null)
			return null;
		String[] tokens = theQuery.split("&");
		Map<String, String> query = new HashMap<String, String>(tokens.length);
		for(String s : tokens)
		{
			int equals = s.indexOf('=');
			if(equals > 0)
				query.put(URLDecoder.decode(s.substring(0, equals), StandardCharsets.UTF_8), URLDecoder.decode(s.substring(equals + 1), StandardCharsets.UTF_8));
			else
			{
				String decoded = URLDecoder.decode(s, StandardCharsets.UTF_8);
				query.put(decoded, decoded);
			}
		}
		return query;
	}
	
	public static final Map<String, String> parseFormPost(String theQuery)
	{
		String[] tokens = theQuery.split("&");
		Map<String, String> query = new HashMap<String, String>(tokens.length);
		for(String s : tokens)
		{
			int equals = s.indexOf('=');
			if(equals > 0)
				query.put(URLDecoder.decode(s.substring(0, equals), StandardCharsets.UTF_8), URLDecoder.decode(s.substring(equals + 1), StandardCharsets.UTF_8));
			else
			{
				String decoded = URLDecoder.decode(s, StandardCharsets.UTF_8);
				query.put(decoded, decoded);
			}
		}
		return query;
	}
	
	public static synchronized void printStackTrace(OutputStream os) throws IOException
	{
		StackTraceElement[] stack = Thread.currentThread().getStackTrace();
		byte[] at = "\tat ".getBytes();
		byte[] eol = System.getProperty("line.separator").getBytes();
		for(int q = 0; q < stack.length; q++)
		{
			if(q == 0 && stack[q].getModuleName().equals("java.base") && stack[q].getClassName().equals("java.lang.Thread"))
				continue; // don't care about java.base/java.lang.Thread.getStackTrace(Thread.java:1610)
			os.write(at);
			os.write(stack[q].toString().getBytes());
			os.write(eol);
		}
	}
	
	public static synchronized void printStackTrace(PrintStream ps)
	{
		StackTraceElement[] stack = Thread.currentThread().getStackTrace();
		for(int q = 0; q < stack.length; q++)
		{
			if(q == 0 && stack[q].getModuleName().equals("java.base") && stack[q].getClassName().equals("java.lang.Thread"))
				continue; // don't care about java.base/java.lang.Thread.getStackTrace(Thread.java:1610)
			ps.printf("\tat %s\n", stack[q].toString());
		}
	}
	
	public static synchronized void printStackTrace()
	{
		StackTraceElement[] stack = Thread.currentThread().getStackTrace();
		for(int q = 0; q < stack.length; q++)
		{
			if(q == 0 && stack[q].getModuleName().equals("java.base") && stack[q].getClassName().equals("java.lang.Thread"))
				continue; // don't care about java.base/java.lang.Thread.getStackTrace(Thread.java:1610)
			System.err.printf("\tat %s\n", stack[q].toString());
		}
	}
	
	public static final String relativeDate(Date now, Date then)
	{
		if(Math.abs(now.getTime() - then.getTime()) < 1000)
			return "just now";
		else if(now.after(then))
			return timeDistBetween(now, then) + " ago";
		else
			return "in " + timeDistBetween(then, now);
	}
	
	private static final String timeDistBetween(Date now, Date then)
	{
		long dist = now.getTime() - then.getTime();
		if(dist < 1000)
			return String.format("%d millisecond%s", dist, dist > 1 ? "s" : "");
		dist /= 1000;
		if(dist < 60)
			return String.format("%d second%s", dist, dist > 1 ? "s" : "");
		dist /= 60;
		if(dist < 60)
			return String.format("%d minute%s", dist, dist > 1 ? "s" : "");
		dist /= 60;
		if(dist < 24)
			return String.format("%d hour%s", dist, dist > 1 ? "s" : "");
		dist /= 24;
		if(dist < 30)
			return String.format("%d day%s", dist, dist > 1 ? "s" : "");
		if(dist >= 365)
		{
			dist /= 365;
			return String.format("%d year%s", dist, dist > 1 ? "s" : "");
		}
		dist /= 30;
		return String.format("%d month%s", dist, dist > 1 ? "s" : "");
	}
	
	public static final void writeDirectoryToZipOutputStream(Path theDirectory, ZipOutputStream output)
	{
		try {
			if(!Files.exists(theDirectory))
				return;
			output.setLevel(9);
			System.out.printf("Started zipping directory %s to .zip\n", theDirectory.toString());
			/*Files.walk(theDirectory).filter((path) -> Files.isRegularFile(path)).sequential().forEach((p) -> {
				try {
					Path newZipName = theDirectory.relativize(p);
					System.out.printf("Writing file \'%s\'... ", newZipName);
					System.out.flush();
					
					ZipEntry entry = new ZipEntry(newZipName.toString());
					entry.setLastModifiedTime(Files.getLastModifiedTime(p));
					output.putNextEntry(entry);
					Files.copy(p, output);
					output.closeEntry();
					System.out.printf("done\n");
					System.out.flush();
				} catch (IOException e) {
					e.printStackTrace();
				}
			});*/
			Pattern onlySlashes = Pattern.compile("/*");
			Files.walk(theDirectory).sequential().forEach((p) -> {
				try {
					System.out.printf("Processing object \'%s\'... ", p.toString());
					System.out.flush();
					Path newZipName = theDirectory.relativize(p);
					
					if(Files.isRegularFile(p))
					{
						System.out.printf("Writing file \'%s\'... ", newZipName);
						System.out.flush();
						ZipEntry entry = new ZipEntry(newZipName.toString());
						entry.setLastModifiedTime(Files.getLastModifiedTime(p));
						output.putNextEntry(entry);
						Files.copy(p, output);
						output.closeEntry();
					}
					else if(Files.isDirectory(p))
					{
						String name = newZipName.toString();
						if(onlySlashes.matcher(name).matches())
						{
							System.out.printf("Skipping root directory \'%s\'... ", name);
						}
						else
						{
							if(!name.endsWith("/"))
								name += "/";
							System.out.printf("Writing directory \'%s\'... ", name);
							System.out.flush();
							ZipEntry entry = new ZipEntry(name);
							entry.setLastModifiedTime(Files.getLastModifiedTime(p));
							output.putNextEntry(entry);
							output.closeEntry();
						}
					}
					else
					{
						System.out.printf("Skipping unknown filesystem object \'%s\'... ", newZipName);
					}
					System.out.printf("done\n");
					System.out.flush();
				} catch (IOException e) {
					e.printStackTrace();
				}
			});
			output.close();
			System.out.printf("Successfully finished zipping directory %s to .zip\n", theDirectory.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static final void writeDirectoryToZipOutputStream(File theDirectory, ZipOutputStream output)
	{
		writeDirectoryToZipOutputStream(theDirectory.toPath(), output);
	}
	
	public static final void serveStream(HttpExchange exchange, InputStream is, long len) throws IOException
	{
		Headers sendhead = exchange.getResponseHeaders();
		sendhead.add("Cache-Control", "max-age=0");
		//sendhead.add("Content-Type", "application/octet-stream");
		if(exchange.getRequestMethod().equals("HEAD"))
		{
			exchange.sendResponseHeaders(200, -1);
			is.close();
			return;
		}
		exchange.sendResponseHeaders(200, len);
		//BufferedOutputStream os = new BufferedOutputStream(exchange.getResponseBody());
		OutputStream os = exchange.getResponseBody();
		byte[] buf = new byte[65535];
		int read;
		while((read = is.read(buf)) > 0)
			os.write(buf, 0, read);
		is.close();
		os.flush();
		os.close();
		exchange.close();
		System.out.println("BufferedOutputStream was closed");
	}
	
	public static final <T>boolean never(T unused)
	{
		return false;
	}
	
	public static final <T>boolean always(T unused)
	{
		return true;
	}
}
