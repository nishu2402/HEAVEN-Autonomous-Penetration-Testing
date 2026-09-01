// HEAVEN synthetic SAST fixture (authored by HEAVEN, MIT-licensed).
// Not part of the OWASP Benchmark corpus; mirrors its true/safe shape so the
// scorer + Java rules can be exercised hermetically, without the GPL corpus.
package heaven.sastfixtures;
import javax.servlet.http.*;
import java.io.*;
public class Case04 extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("X");
    java.sql.Statement st = getConnection().createStatement();
    st.executeQuery("SELECT * FROM users WHERE name = '" + param + "'");
  }
  java.sql.Connection getConnection() { return null; }
}
