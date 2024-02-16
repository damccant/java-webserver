package web;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import com.sun.net.httpserver.HttpExchange;

import sun.misc.Unsafe;
import web.WebServer.IOStream;

/**
 * This class exists because the <code>com.sun.net.httpserver.HttpExchange</code>
 * API has no way to access the underlying <code>InputStream</code> and
 * <code>OutputStream</code>, which is needed for the WebSocket functionality.
 * <p>
 * This class uses the <code>Unsafe</code> API to force allow access to the
 * underlying implementation.
 * <p>
 * Before reading this class, you should keep in mind that that this is called
 * <code>HttpExchange<b>Hack</b></code> for a reason
 * @author Derek McCants
 */
public class HttpExchangeHack
{
	/**
	 * "Undefined behavior"? I think you mean, "designed effects"
	 */
	private static Unsafe unsafe;
	static
	{
		try {
			Field f = Unsafe.class.getDeclaredField("theUnsafe");
			f.setAccessible(true);
			unsafe = (Unsafe)f.get(null);
		} catch (NoSuchFieldException | IllegalArgumentException | IllegalAccessException e) {
			e.printStackTrace();
		}
	};
	
	/**
	 * Retrieves the specified field from the specified parent object,
	 * bypassing all Java access controls and security checks.
	 * <p>
	 * Or crashes the underlying JVM, depending on what mood we're in.
	 * <p>
	 * This works by systematically corrupting the memory around the desired
	 * object until we overwrite the override flag, which allows us to ignore
	 * all Java security checks.
	 * @param f The private field to access
	 * @param toObtainFrom The object to access the field from
	 * @return The desired object, or maybe not at all if the JVM realizes
	 * we're being naughty
	 * @deprecated You really shouldn't be using this
	 * @implNote Wow, if we're really lucky, this might even work!
	 */
	@Deprecated
	public static final Object hackObjectFromField(Field f, Object toObtainFrom)
	{
		try {
			f.setAccessible(true); // welp, its worth a try
			return f.get(toObtainFrom); // this will work on < java 1.8
		} catch (Exception e) {
			// java > 1.8 will throw an exception, so we need to do some hacks to
			// port it to new versions of java
			try {
				for(int off = 0; off < 100; ++off)
				{
					if(off >= 5 && off <= 11)
						continue; // these offsets just immediately crash the JVM
					//System.err.printf("corrupting offset %d\n", off);
					//System.err.flush(); // in case the JVM crashes before that message can be printed
					int old = unsafe.getInt(f, off); // save the old memory so we can restore it
					unsafe.putInt(f, off, 1); // corrupt the memory, we are trying to overwrite the override flag
					if(f.canAccess(toObtainFrom)) // did we get it?
						return f.get(toObtainFrom); // we got it! return the object!!
					unsafe.putInt(f, off, old); // ok, that didnt work, put it back
				}
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		System.err.printf("failed to hack object!\n");
		return null;
	}
	
	/**
	 * Retrieves the underlying <code>InputStream</code> and
	 * <code>OutputStream</code> from a <code>HttpExchange</code> object.
	 * <p>
	 * Or, depending on the position of the moon and the stars, immediately
	 * crashes the underlying JVM
	 * @param t The <code>HttpExchange</code>
	 * @return Assuming the JVM hasn't crashed or realized we're being naughty
	 * by this point, then the underlying <code>InputStream</code> and
	 * <code>OutputStream</code> wrapped in an <code>IOStream</code> object
	 * @deprecated You really shouldn't be using this
	 * @implNote Wow, if we're really lucky, this might even work!
	 */
	@Deprecated
	public static IOStream hackRawStreamsFromExchange(HttpExchange t)
	{
		try {
			Field exchangeImplField = t.getClass().getDeclaredField("impl"); // illegal access? its not illegal if im only borrowing ;)
			Object exchangeImpl = hackObjectFromField(exchangeImplField, t);
			// steal the ros and ris fields from sun.net.exchangeimpl
			OutputStream ros = (OutputStream)hackObjectFromField(exchangeImpl.getClass().getDeclaredField("ros"), exchangeImpl);
			InputStream ris = (InputStream)hackObjectFromField(exchangeImpl.getClass().getDeclaredField("ris"), exchangeImpl);
			return new IOStream(ris, ros);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}