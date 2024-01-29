package web;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import com.sun.net.httpserver.HttpExchange;
/*import sun.net.httpserver.HttpExchangeImpl;
import sun.net.httpserver.HttpsExchangeImpl;
import sun.net.httpserver.ExchangeImpl;*/

import sun.misc.Unsafe;
import web.WebServer.IOStream;

/**
 * "Undefined behavior"? I think you mean, "designed effects"
 * <p>
 * The fact that this class even exists should highlight the shortcomings of
 * the <code>com.sun.net.httpserver</code> API
 * <p>
 * Before reading this class, you should keep in mind that that this is called
 * <code>HttpExchange<b>Hack</b></code> for a reason
 * @author dmccants
 *
 */
public class HttpExchangeHack
{
	/**
	 * Yeah, one line in and things are already going sideways
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
	 * Or crashes the underlying JVM, depending on what mood we're in
	 * @param f The private field to access
	 * @param toObtainFrom The object to access the field from
	 * @return The desired object, or maybe not at all if the JVM realizes
	 * we're being naughty
	 * @deprecated You really shouldn't be using this
	 * @implNote Wow, if we're really lucky, this might even work!
	 */
	public static final Object hackObjectFromField(Field f, Object toObtainFrom)
	{
		try {
			f.setAccessible(true); // welp, its worth a try
			return f.get(toObtainFrom); // this will work on < java 1.8
		} catch (Exception e) {
			try {
				//System.out.printf("f.getClass() = \"%s\"\nf.getClass().getSuperclass() = \"%s\"\n", f.getClass(), f.getClass().getSuperclass());
				//for(int i = 0; i < 100; ++i)
				//	System.out.printf("f + %02d = 0x%08x\n", i, unsafe.getInt(f, i));
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
	public static IOStream hackRawStreamsFromExchange(HttpExchange t)
	{
		//Class<?> impl_class = t.getClass();
		//System.out.printf("class is \"%s\"\n", impl_class);
		try {
			//System.out.printf("here 1\n");
			//Method getExchangeImplMethod = t.getClass().getDeclaredMethod("getExchangeImpl"); // or steal the impl field directly
			
			Field exchangeImplField = t.getClass().getDeclaredField("impl"); // illegal access? its not illegal if im only borrowing ;)
			Object exchangeImpl = hackObjectFromField(exchangeImplField, t);
			//System.out.printf("exchangeimpl (hopefully) is type \"%s\"\n", exchangeImpl.getClass());
			// steal the ros and ris fields from sun.net.exchangeimpl
			OutputStream ros = (OutputStream)hackObjectFromField(exchangeImpl.getClass().getDeclaredField("ros"), exchangeImpl);
			InputStream ris = (InputStream)hackObjectFromField(exchangeImpl.getClass().getDeclaredField("ris"), exchangeImpl);
			return new IOStream(ris, ros);
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
