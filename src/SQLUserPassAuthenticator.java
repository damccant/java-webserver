import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import web.WebServer.UserPassAuthenticator;

/**
 * Authenticates a user against credentials stored in a SQL database
 * @author Derek McCants
 *
 */
public class SQLUserPassAuthenticator extends UserPassAuthenticator {
	
	private static final String SQL_QUERY = "SELECT COUNT(*) FROM UserApplicant WHERE userId = ? AND hashed_pass = ?";

	public SQLUserPassAuthenticator(String realm) {
		super(realm);
	}
	
	private static final MessageDigest getMessageDigest()
	{
		try {
			return MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace(); // this should never happen
			return null;
		}
	}
	
	private static final String hash(String what)
	{
		byte[] bin_hash = getMessageDigest().digest(what.getBytes());
		StringBuilder sb = new StringBuilder();
		for(byte b : bin_hash)
			sb.append(String.format("%02x", b));
		return sb.toString();
	}

	@Override
	public boolean checkCredentials(String username, String password) {
		Connection conn = null;
		try {
			conn = Main.getDatabaseConnection();
			PreparedStatement stmt = conn.prepareCall(SQL_QUERY);
			stmt.setString(1, username);
			// hash the password for extra security
			String hashed_pass = hash(password);
			stmt.setString(2, hashed_pass);
			//System.out.printf("[debug] Trying to login %s with password %s (%s)\n", username, password, hashed_pass);
			//System.out.printf("[debug] %s\n", stmt.toString());
			ResultSet rs = stmt.executeQuery();
			rs.next();
			//System.out.printf("[debug] Authentication result was %d\n", rs.getInt(1));
			if(rs.getInt(1) > 0)
			{
				this.loggedUser = username;
				return true;
			}
			return false;
		} catch (SQLException e) {
			e.printStackTrace();
			return false;
		} finally {
			if(conn != null)
				try {
					conn.close(); // this is very important!!
				} catch (Exception e) {
					e.printStackTrace();
				}
		}
	}

}
