package geomesa.sec.gs.filter

import java.io.IOException
import java.security.Principal
import java.util.Collections
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import javax.servlet.{FilterChain, ServletRequest, ServletResponse}

import com.typesafe.scalalogging.slf4j.Logging
import org.geoserver.security.filter.GeoServerRequestHeaderAuthenticationFilter
import org.geoserver.security.impl.GeoServerRole
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken

import scala.util.{Failure, Success, Try}

class ProxiedAuthHeaderFilter extends GeoServerRequestHeaderAuthenticationFilter with Logging {

  override def doFilter(req: ServletRequest, resp: ServletResponse, fc: FilterChain): Unit =
    Try {
       Option(SecurityContextHolder.getContext.getAuthentication).getOrElse {
        val httpReq = req.asInstanceOf[HttpServletRequest]
        val headerValue = httpReq.getHeader(getPrincipalHeaderAttribute)
        logger.debug(s"ProxiedAuthHeader: $getPrincipalHeaderAttribute=$headerValue")
        val proxiedUser = parseHeader(headerValue)
        val gsAuthorities = Collections.singleton(GeoServerRole.ADMIN_ROLE)
        new PreAuthenticatedAuthenticationToken(proxiedUser, null, gsAuthorities)
      }
    } match {
      case Success(result) =>
        SecurityContextHolder.getContext.setAuthentication(result)
        fc.doFilter(req, resp)
      case Failure(ex) =>
        logger.error("Error setting security context with Proxied Auth Header", ex)
        sendError(resp)
    }

  /** Default implementation is format "user:auth1,auth2,auth3" **/
  def parseHeader(headerValue: String): ProxiedUser = {
    val split = headerValue.split(":")
    ProxiedUser(split(0), split(1).split(",").toSeq)
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

case class ProxiedUser(userName: String, visibilites: Seq[String]) extends UserDetails {

}
