import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

/**
 * 
 * @author Derek McCants
 *
 */
public class UserApplicant
{
	private String userId;
	/*private String hashed_pass;
	private String education;
	private float jobExp;
	private String resume;*/
	
	public UserApplicant(String userId)
	{
		this.userId = userId;
	}
	
	/*public void setAllFields(String password, String education, Float jobExp, String resume)
	{
		Connection conn = null;
		try {
			conn = Main.getDatabaseConnection();
			PreparedStatement stmt = conn.prepareCall("UPDATE UserApplicant SET;");
			stmt.setString(1, userId);
			stmt.setString(2, hash(password));
			if(education != null)
				stmt.setString(3, education);
			else
				stmt.setNull(3, Types.VARCHAR);
			if(jobExp != null)
				stmt.setFloat(4, jobExp);
			else
				stmt.setNull(4, Types.FLOAT);
			if(resume != null)
				stmt.setString(5, resume);
			else
				stmt.setNull(5, Types.VARCHAR);
			int ret = stmt.executeUpdate();
			if(ret > 0)
				return new UserApplicant(userId);
			return null;
		} catch (SQLException e) {
			e.printStackTrace();
			return null;
		} finally {
			if(conn != null)
				try {
					conn.close(); // this is very important!!
				} catch (Exception e) {
					e.printStackTrace();
				}
		}
	}*/
	
	public static UserApplicant registerNewUser(String userId, String password, String education, Float jobExp, String resume)
	{
		Connection conn = null;
		try {
			conn = Main.getDatabaseConnection();
			PreparedStatement stmt = conn.prepareCall("INSERT INTO UserApplicant VALUES (?, ?, ?, ?, ?);");
			stmt.setString(1, userId);
			stmt.setString(2, hash(password));
			if(education != null)
				stmt.setString(3, education);
			else
				stmt.setNull(3, Types.VARCHAR);
			if(jobExp != null)
				stmt.setFloat(4, jobExp);
			else
				stmt.setNull(4, Types.FLOAT);
			if(resume != null)
				stmt.setString(5, resume);
			else
				stmt.setNull(5, Types.VARCHAR);
			int ret = stmt.executeUpdate();
			if(ret > 0)
				return new UserApplicant(userId);
			return null;
		} catch (SQLException e) {
			e.printStackTrace();
			return null;
		} finally {
			if(conn != null)
				try {
					conn.close(); // this is very important!!
				} catch (Exception e) {
					e.printStackTrace();
				}
		}
	}
	
	public boolean deleteUser()
	{
		Connection conn = null;
		try {
			conn = Main.getDatabaseConnection();
			PreparedStatement stmt = conn.prepareCall("DELETE FROM UserApplicant WHERE userId = ?;");
			stmt.setString(1, userId);
			return stmt.executeUpdate() > 0;
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
	
	private <T>T getProperty(String prop, Class<T> type)
	{
		Connection conn = null;
		try {
			conn = Main.getDatabaseConnection();
			PreparedStatement stmt = conn.prepareCall("SELECT " + prop + " FROM UserApplicant WHERE userId = ?");
			stmt.setString(1, userId);
			//System.out.printf("[debug] Trying to login %s with password %s (%s)\n", username, password, hashed_pass);
			//System.out.printf("[debug] %s\n", stmt.toString());
			ResultSet rs = stmt.executeQuery();
			rs.next();
			//System.out.printf("[debug] Authentication result was %d\n", rs.getInt(1));
			return (T)rs.getObject(1, type);
		} catch (SQLException e) {
			e.printStackTrace();
			return null;
		} finally {
			if(conn != null)
				try {
					conn.close(); // this is very important!!
				} catch (Exception e) {
					e.printStackTrace();
				}
		}
	}
	
	private <T>boolean setProperty(String prop, T value)
	{
		Connection conn = null;
		try {
			conn = Main.getDatabaseConnection();
			PreparedStatement stmt = conn.prepareCall("UPDATE UserApplicant SET " + prop + " = ? WHERE userId = ?");
			stmt.setObject(1, value);
			stmt.setString(2, userId);
			System.out.printf("[debug] %s\n", stmt.toString());
			return stmt.executeUpdate() > 0;
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
	
	public String getUserId()
	{
		return userId;
	}
	
	public String getEducation()
	{
		return getProperty("education", String.class);
	}
	
	public Float getJobExp()
	{
		return getProperty("jobExp", Float.class);
	}
	
	public String getResume()
	{
		return getProperty("resume", String.class);
	}
	
	public boolean setPassword(String newPass)
	{
		return setHashedPass(hash(newPass));
	}
	
	private boolean setHashedPass(String newHash)
	{
		return setProperty("hashed_pass", newHash);
	}
	
	public boolean setEducation(String education)
	{
		return setProperty("education", education);
	}
	
	public boolean setJobExp(float jobExp)
	{
		return setProperty("jobExp", jobExp);
	}
	
	public boolean setResume(String resume)
	{
		return setProperty("resume", resume);
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
	
	public class ReadOnlyCachedUserApplicant
	{
		public String userId;
		public String education;
		public Float jobExp;
		public String resume;
	}
	public ReadOnlyCachedUserApplicant getAllFields()
	{
		Connection conn = null;
		try {
			conn = Main.getDatabaseConnection();
			PreparedStatement stmt = conn.prepareCall("SELECT * FROM UserApplicant WHERE userId = ?");
			stmt.setString(1, userId);
			ResultSet rs = stmt.executeQuery();
			rs.next();
			ReadOnlyCachedUserApplicant u = new ReadOnlyCachedUserApplicant();
			u.userId = rs.getString("userId");
			u.education = rs.getString("education");
			u.jobExp = rs.getFloat("jobExp");
			u.resume = rs.getString("resume");
			return u;
		} catch (SQLException e) {
			e.printStackTrace();
			return null;
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
