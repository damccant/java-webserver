package util;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeUnit;

public final class OS_Specific {
	public static final String OS = System.getProperty("os.name").toLowerCase();
	public static final boolean isWindows()
	{
		return OS.contains("win");
	}
	public static final boolean isMac()
	{
		return OS.contains("mac");
	}
	public static final boolean isUnix()
	{
		return OS.contains("nix") || OS.contains("nux") || OS.contains("aix");
	}
	public static final boolean isSolaris()
	{
		return OS.contains("sunos");
	}
	public static final String getShellExec()
	{
		if(isWindows())
			return "cmd";
		return "/bin/bash";
	}
	public static final String getShellExample()
	{
		if(isWindows())
			return "dir";
		return "ls -alh";
	}
	public static final String getAllIpAddressInfo()
	{
		if(isWindows())
			try {
				return runSysCmd("ipconfig", "/all");
			} catch (IOException e) {
				e.printStackTrace();
				return "could not obtain IP address";
			}
		try {
			return runSysCmd("ip", "a");
		} catch (IOException e) {
			e.printStackTrace();
			try {
				return runSysCmd("ifconfig");
			} catch (IOException e1) {
				e1.printStackTrace();
				return "could not obtain IP address";
			}
		}
	}
	public static final String whoami = System.getProperty("user.name");
	private static final String getHostname()
	{
		try {
			return InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return "localhost";
		}
	}
	public static final String hostname = getHostname();
	private static final String runSysCmd(String... s) throws IOException
	{
		ProcessBuilder pb = new ProcessBuilder(s);
		Process p = pb.start();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		InputStream is = new BufferedInputStream(p.getInputStream());
		is.transferTo(baos);
		is.close();
		try {
			p.waitFor(5, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			throw new IOException(e);
		}
		if(p.isAlive())
			p.destroyForcibly();
		return baos.toString();
	}
	
}
