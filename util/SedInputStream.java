package util;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.io.FilterInputStream;

/**
 * <code>SedInputStream</code> implements an <code>FilterInputStream</code>
 * that recognizes a sequence of characters and replaces them on the fly.
 * <p>
 * <b>NOTE:</b> This class is not thread-safe
 * @author dmccants
 * @version 1.0
 *
 */
public class SedInputStream extends FilterInputStream
{
	/**
	 * Creates a new <code>SedInputStream</code> that gets its data
	 * "the haystack" from the specified <code>InputStream</code>
	 * @param is the underlying <code>InputStream</code> to read the data from
	 */
	public SedInputStream(InputStream is)
	{
		super(is);
		mappings = new HashMap<byte[], byte[]>();
		buffer = new ArrayDeque<Integer>();
		currentReplace = null;
		pos = 0;
		maxneedlesize = 0;
	}
	
	/**
	 * Sets up this <code>SedInputStream</code> to replace the specified
	 * "needle" String with the other specified String.
	 * <p>
	 * Note that no searching or replacing actually happens here, instead the
	 * <code>InputStream</code> is automatically searched as you call
	 * <code>read()</code>.
	 * @param needle The <code>String</code> to search the
	 * <code>InputStream</code> for
	 * @param replacewith The <code>String</code> to replace any matches with
	 * @return a reference to itself, this allows for chaining commands like:<br>
	 * <code>SedInputStream sis = new SedInputStream(is).replaceAll("needle", "something else").replaceAll("whatever", "not whatever");</code>
	 * @throws IllegalArgumentException if needle is an empty String
	 */
	public SedInputStream replaceAll(String needle, String replacewith)
	{
		return replaceAll(needle.getBytes(), replacewith.getBytes());
	}
	
	public SedInputStream replaceAll(byte[] needle, byte[] replacewith)
	{
		if(needle.length < 1)
			throw new IllegalArgumentException("Cannot replace empty string with something, empty string matches everywhere!!");
		mappings.put(needle, replacewith);
		if(needle.length > maxneedlesize)
			maxneedlesize = needle.length;
		return this;
	}
	
	/**
	 * Sets up the <code>SedInputStream</code> to stop replacing instances
	 * of the specified String that was previously setup by
	 * <code>replaceAll</code>
	 * @param needle The <code>String</code> to stop searching for
	 * @return a reference to this <code>SedInputStream</code>
	 */
	public SedInputStream stopReplacing(String needle)
	{
		mappings.remove(needle.getBytes());
		// TODO: shrink max needle size if needed
		return this;
	}
	
	private Map<byte[], byte[]> mappings;
	private byte[] currentReplace;
	private int pos;
	private int maxneedlesize;
	private Deque<Integer> buffer;
	
	@Override
	public int read(byte[] b) throws IOException
	{
		return read(b, 0, b.length);
	}
	
	/**
	 * Reads up to <code>len</code> bytes of data from this input stream
	 * into an array of bytes. If <code>len</code> is not zero, the method
	 * blocks until some input is available; otherwise, no
	 * bytes are read and </code>0</code> is returned.
	 * @param buffer The <code>byte[]</code> buffer to read data into
	 * @param off The offset to start inserting bytes into
	 * @param len The maximum number of bytes to read.  The actual number
	 * of bytes read is returned as an integer
	 * @throws IOException if the underlying <code>InputStream</code> throws an
	 * <code>IOException</code>
	 * @see InputStream#read(byte[], int, int)
	 */
	@Override
	public int read(byte[] buffer, int off, int len) throws IOException
	{
		if(len < 1)
			return 0;
		int b;
		int q = 0;
		int extra = 0;
		while((q + extra) < len && ((b = read()) >= 0))
		{
			if(b > 255)
				buffer[off + q + extra++] = (byte)((b >> 8) & 0xff);
			if(q + extra < len)
				buffer[off + q + extra] = (byte)(b & 0xff);
			q++;
		}
		if(q < 1)
			return -1;
		return q;
	}
	@Override
	public int read() throws IOException
	{
		if(currentReplace != null && pos < currentReplace.length)
			return currentReplace[pos++];
		else if(currentReplace != null && pos >= currentReplace.length)
			currentReplace = null;
		if(maxneedlesize < 1)
		{
			if(buffer == null || buffer.isEmpty())
				return in.read();
			else
				return buffer.pop();
		}
		while(buffer.size() < maxneedlesize)
			buffer.add(in.read());
		for(Entry<byte[], byte[]> needle : mappings.entrySet())
		{
			if(dequeEqualsBytes(buffer, needle.getKey()))
			{
				for(int t = 0; t < needle.getKey().length; t++)
					buffer.pop();
				currentReplace = needle.getValue();
				pos = 0;
				return currentReplace.length > 0 ? currentReplace[pos++] : read();
			}
		}
		return buffer.pop();
	}
	
	private static final boolean dequeEqualsBytes(Deque<Integer> b, byte[] t)
	{
		if(b.isEmpty())
			return false;
		Iterator<Integer> i = b.iterator();
		int q = 0;
		for(q = 0; q < Math.min(b.size(), t.length); q++)
			if(i.next() != t[q])
				return false;
		return true;
	}
	
	/*private static final String dequeToString(Deque<Integer> b)
	{
		if(b.isEmpty())
			return "<empty>";
		StringBuilder sb = new StringBuilder();
		for(int q : b)
			sb.append((char)(q & 0xff));
		return sb.toString();
	}*/
}
