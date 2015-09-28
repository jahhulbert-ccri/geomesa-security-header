package geomesa.sec.gs.filter

import java.io.IOException
import java.util.Collections
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import javax.servlet.{FilterChain, ServletRequest, ServletResponse}

import com.typesafe.scalalogging.slf4j.Logging
import org.geoserver.security.filter.GeoServerRequestHeaderAuthenticationFilter
import org.geoserver.security.impl.GeoServerRole
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken

class ProxiedAuthHeaderFilter extends GeoServerRequestHeaderAuthenticationFilter with Logging {

  override def doFilter(req: ServletRequest, resp: ServletResponse, fc: FilterChain): Unit = {
    if (SecurityContextHolder.getContext.getAuthentication  == null) {
      val httpReq = req.asInstanceOf[HttpServletRequest]
      val headerValue = httpReq.getHeader(getPrincipalHeaderAttribute)
      logger.trace(s"Principal header $getPrincipalHeaderAttribute value: $headerValue")
      if (headerValue != null) {
        val parsedInfo = getPrincipalAndCreds(headerValue)
        val principal: String = parsedInfo._1
        val creds: IndexedSeq[String] = parsedInfo._2
        val auths: java.util.Collection[GeoServerRole] = Collections.singleton(GeoServerRole.ADMIN_ROLE)
        val result = new PreAuthenticatedAuthenticationToken(principal, creds, auths)
      } else {
        sendError(resp)
      }
    }
    fc.doFilter(req, resp)
  }

  private def getPrincipalAndCreds(headerValue: String) = {
    val split = headerValue.split(":")
    (split(0), split(1).split(","))
  }

  @throws(classOf[IOException])
  private def sendError(resp: ServletResponse) = {
    resp.asInstanceOf[HttpServletResponse].setStatus(403)
    resp.setContentType("text/plain")
    val out = resp.getWriter
    out.println("Error with security you can't get in here buddy.\n")
    out.flush()
  }

}
