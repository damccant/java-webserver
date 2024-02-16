import java.io.IOException;
import java.util.Map;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;

import util.Helper;
import web.HtmlPageFactory;
import web.WebServer;
import web.WebServer.CustomAuthorizedHttpHandler;
import web.WebServer.UserPassAuthenticator;

public class HomePageHandler extends CustomAuthorizedHttpHandler {

	public HomePageHandler(UserPassAuthenticator ba) {
		super(ba);
		// TODO Auto-generated constructor stub
	}
	
	/**
	 * Handles the incoming request.  Note that this method is ONLY called if
	 * the user is signed in, otherwise, the Sign-In message is displayed again.
	 * <p>
	 * If and only if the user successfully signs in, then this method is called.
	 * @param t The <code>HttpExchange</code> of this request
	 * @param user The username of the signed on user
	 */
	@Override
	public void handleAuthorized(HttpExchange t, String username) throws IOException
	{
		UserApplicant user = new UserApplicant(username);
		if(t.getRequestMethod().equals("GET"))
			displayInterface(t, user);
		else if(t.getRequestMethod().equals("POST"))
			handleUpdate(t, user);
		else
			WebServer.handleErrorChecked(t, 400, new Exception("Unknown HTTP request method"));
	}

	public void displayInterface(HttpExchange t, UserApplicant user) throws IOException
	{
		HtmlPageFactory hpf = new HtmlPageFactory();
		UserApplicant.ReadOnlyCachedUserApplicant userInfo = user.getAllFields();
		HttpContext ctx = t.getHttpContext();
		hpf.startMainBody();
		hpf.createTitle("Hello, " + userInfo.userId + "!");
		hpf.print("<script>"
				+ "function logout(c) {\r\n"
				+ "  var a, b = \"You should be logged out now.\";\r\n"
				+ "  try {\r\n"
				+ "    a = document.execCommand(\"ClearAuthenticationCache\")\r\n"
				+ "  } catch (d) {\r\n"
				+ "  }\r\n"
				+ "  a || ((a = window.XMLHttpRequest ? new window.XMLHttpRequest : window.ActiveXObject ? new ActiveXObject(\"Microsoft.XMLHTTP\") : void 0) ? (a.open(\"HEAD\", c || location.href, !0, \"logout\", (new Date).getTime().toString()), a.send(\"\"), a = 1) : a = void 0);\r\n"
				+ "  a || (b = \"Your browser is too old or too weird to support log out functionality. Close all windows and restart the browser.\");\r\n"
				+ "  alert(b)\r\n"
				+ "}"
				+ "</script>");
		hpf.printf("<button onclick=\"logout('/'); location.reload();\">Log out</button>", ctx.getPath());
		hpf.createElement("div", Map.of("class", "row"));
		hpf.createElement("div", Map.of("class", "col-lg-12"));
		hpf.createElement("table");
		hpf.printf("<tr>\r\n"
				+ "	<form method=\"POST\">\r\n"
				+ "		<td>\r\n"
				+ "			<label for=\"password\">Change Password:</label>\r\n"
				+ "		</td>\r\n"
				+ "		<td>\r\n"
				+ "			<input name=\"password\" />\r\n"
				+ "		</td>\r\n"
				+ "		<td>\r\n"
				+ "			<input type=\"submit\" />\r\n"
				+ "		</td>\r\n"
				+ "	</form>\r\n"
				+ "</tr>\r\n"
				+ "<tr>\r\n"
				+ "	<form method=\"POST\">\r\n"
				+ "		<td>	\r\n"
				+ "			<label for=\"education\">Education:</label>\r\n"
				+ "		</td>\r\n"
				+ "		<td>\r\n"
				+ "			<input name=\"education\" value=\"%s\" />\r\n"
				+ "		</td>\r\n"
				+ "		<td>\r\n"
				+ "			<input type=\"submit\" />\r\n"
				+ "		</td>\r\n"
				+ "	</form>\r\n"
				+ "</tr>\r\n"
				+ "<tr>\r\n"
				+ "	<form method=\"POST\">\r\n"
				+ "		<td>	\r\n"
				+ "			<label for=\"jobExp\">Job Expierence (years):</label>\r\n"
				+ "		</td>\r\n"
				+ "		<td>\r\n"
				+ "			<input name=\"jobExp\" value=\"%s\" />\r\n"
				+ "		</td>\r\n"
				+ "		<td>\r\n"
				+ "			<input type=\"submit\" />\r\n"
				+ "		</td>\r\n"
				+ "	</form>\r\n"
				+ "</tr>", userInfo.education, userInfo.jobExp);
		hpf.closeElement(); // table
		hpf.printf("<form method=\"POST\">\r\n"
				+ "	<label for=\"resume\">Resume:</label>\r\n"
				+ "	<textarea name=\"resume\">%s</textarea>\r\n"
				+ "	<input type=\"submit\" />\r\n"
				+ "</form>", userInfo.resume);
		hpf.closeAllElements();
		hpf.close();
		hpf.sendResponseChecked(200, t);
	}
	
	public void handleUpdate(HttpExchange t, UserApplicant user) throws IOException
	{
		System.out.println("here in handleUpdate()");
		
		Map<String, String> query = Helper.parseFormPost(new String(t.getRequestBody().readAllBytes()));
		query.forEach((key, value) -> {
			try {
			if(key.equals("password"))
				if(!user.setPassword(value))
					System.err.printf("[warn] Setting password failed!\n");
			else if(key.equals("education"))
				if(!user.setEducation(value))
					System.err.printf("[warn] Setting education failed!\n");
			else if(key.equals("jobExp"))
				try {
					if(!user.setJobExp(Float.parseFloat(value)))
						System.err.printf("[warn] Setting jobExp failed!\n");
				} catch (NumberFormatException e) {}
			else if(key.equals("resume"))
				if(!user.setResume(value))
					System.err.printf("[warn] Setting resume failed!\n");
			else
				System.err.printf("[warn] Failed to set unknown key \"%s\"\n", key);
			} catch (Exception e) {e.printStackTrace();}
		});
		WebServer.redirectChecked(t, t.getHttpContext().getPath());
		//displayInterface(t, user);
	}
}
