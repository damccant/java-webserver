package util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class HtmlEscapedInputStream extends FilterInputStream
{
	private byte[] thisEscape = null;
	private int thisPos = 0;
	/*public static final String escapeHTML(String str)
	{
		return str.codePoints().mapToObj(c -> c > 127 || "/\"'<>&".indexOf(c) != -1 ?
				"&#" + c + ";" : new String(Character.toChars(c))).collect(Collectors.joining());
	}*/

	public HtmlEscapedInputStream(InputStream in)
	{
		super(in);
		thisEscape = null;
		thisPos = 0;
	}
	
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
		if(thisEscape != null)
		{
			if(thisPos < thisEscape.length)
				return thisEscape[thisPos++];
			thisEscape = null;
			thisPos = 0;
		}
		int c = in.read();
		if(c < 0)
			return -1;
		if(c > 127 || "/\"'<>&".indexOf(c) != -1)
		{
			if(c < 10)
				thisEscape = new byte[] { '&', '#', (byte) (c + '0'), ';' };
			else if(c < 100)
				thisEscape = new byte[] { '&', '#', (byte) (c / 10 + '0'), (byte) (c % 10 + '0'), ';' };
			else
				thisEscape = new byte[] { '&', '#', (byte) (c / 100 + '0'), (byte) ((c % 100) / 10 + '0'), (byte) (c % 10 + '0'), ';' };
			thisPos = 0;
			return thisEscape[thisPos++];
		}
		return c;
	}
}
