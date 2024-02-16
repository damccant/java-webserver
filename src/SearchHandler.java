import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.URI;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class SearchHandler implements HttpHandler
{
	public PreparedStatement searchCompany;
	
	public void handleStaticSearchPage(HttpExchange exchange)
	{
		
	}
	
	/*public void search(HttpExchange exchange, String category, String query) throws IOException
	{
		boolean all = category.equals("all");
		if(all || category.equals("company"))
			search(exchange, "Company", "companyName");
		if(all || category.equals("posting"))
			search(exchange, "JobPosting", "title");3.
		// TODO: actually generate the HTML
	}*/
	
	private void search(HttpExchange exchange, String table, String query) throws IOException
	{
		Connection conn = null;
		try {
			conn = Main.getDatabaseConnection();
			PreparedStatement searchCompany = conn.prepareStatement("SELECT * FROM COMPANY WHERE companyName LIKE '%?%';");
			searchCompany.setString(1, query);
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			if(conn != null)
				try {
					conn.close();
				} catch (SQLException e) {
					e.printStackTrace();
				}
		}
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException
	{
		URI uri = exchange.getRequestURI();
		String query = uri.getQuery();
		if(query == null)
		{
			handleStaticSearchPage(exchange);
			return;
		}
		String[] tokens = query.split("&");
		String category = "all";
		String searchPhrase = null;
		for(String t : tokens)
		{
			if(t.startsWith("category="))
				category=t.substring("category=".length());
			else if(t.startsWith("query="))
				searchPhrase=t.substring("query=".length());
		}
		if(category == null || searchPhrase == null)
		{
			handleStaticSearchPage(exchange);
			return;
		}
		search(exchange, category, query);
	}

}
