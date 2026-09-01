// HEAVEN synthetic SAST fixture (authored by HEAVEN, MIT-licensed).
// Not part of the OWASP Benchmark corpus; mirrors its true/safe shape so the
// scorer + Java rules can be exercised hermetically, without the GPL corpus.
package heaven.sastfixtures;
import javax.servlet.http.*;
import java.io.*;
public class Case07 extends HttpServlet {
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String param = request.getParameter("X");
    String safe = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
    response.getWriter().println("Hello " + safe);
  }
}
