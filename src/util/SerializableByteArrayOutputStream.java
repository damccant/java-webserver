package util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;

/**
 * Extends the built-in <code>ByteArrayOutputStream</code> and makes it
 * serializable.
 * <p>
 * This allows the <code>ByteArrayOutputStream</code> to be saved and restored
 * to/from the disk using the normal <code>java.io.Serializable</code>
 * interface.
 * @author dmccants
 * @version 1.1
 */
public class SerializableByteArrayOutputStream extends ByteArrayOutputStream implements Serializable
{
	/**
	 * This UID is used to confirm the correct class is being deserialized
	 */
	private static final long serialVersionUID = -6502951639807377600L;
	/*private volatile transient Thread busy;
	public synchronized void busyWait()
	{
		if(busy != null && busy.isAlive() && busy != Thread.currentThread())
			try {
				busy.join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
	}*/
	@Override
	public void write(int c)
	{
		try {
			super.write(c);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	@Override
	public void write(byte[] b, int off, int len)
	{
		try {
			super.write(b, off, len);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	@Override
	public void write(byte[] b)
	{
		try {
			super.write(b);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	/*public void write(int c)
	{
		busyWait();
		busy = Thread.currentThread();
		super.write(c);
		busy = null;
	}
	public void write(byte[] b)
	{
		busyWait();
		busy = Thread.currentThread();
		super.write(b, 0, b.length);
		busy = null;
	}
	public void write(byte[] buf, int off, int size)
	{
		busyWait();
		busy = Thread.currentThread();
		super.write(buf, off, size);
		busy = null;
	}*/
	private synchronized void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException
	{
		//busy = Thread.currentThread();
		long readserialVersionUID = ois.readLong();
		if(readserialVersionUID != serialVersionUID)
			throw new ClassNotFoundException("unknown serialVersionUID " + readserialVersionUID);
		int size = ois.readInt();
		buf = new byte[size];
		count = size;
		ois.readFully(buf, 0, size);
		//System.out.printf("in SerializableByteArrayOutputStream, read %d bytes\n", size());
		//busy = null;
		
		//TODO debug
		readserialVersionUID = ois.readLong();
		if(readserialVersionUID != serialVersionUID)
			throw new ClassNotFoundException("unknown suffix " + readserialVersionUID);
	}
	private synchronized void writeObject(ObjectOutputStream oos) throws IOException
	{
		//busy = Thread.currentThread();
		oos.writeLong(serialVersionUID);
		//System.out.printf("in SerializableByteArrayOutputStream, saving %d bytes\n", size());
		oos.writeInt(size());
		writeTo(oos);
		//busy = null;
		
		//TODO debug
		oos.writeLong(serialVersionUID);
	}
	/**
	 * Writes the contents of the buffer to the specified
	 * <code>OutputStream</code>.
	 * @param os The <code>OutputStream</code> to write to
	 * @throws IOException if the <code>OutputStream</code> throws an
	 * <code>IOException</code>
	 * @throws NullPointerException if <code>os</code> is null
	 */
	public void transferTo(OutputStream os) throws IOException
	{
		os.write(buf, 0, size());
	}
	public byte[] getInternalBuffer()
	{
		return buf;
	}
}