package geomesa.sec.provider

import java.io.Serializable
import java.util

import com.typesafe.scalalogging.slf4j.Logging
import org.apache.accumulo.core.security.Authorizations
import org.locationtech.geomesa.security.AuthorizationsProvider
import org.springframework.security.core.context.SecurityContextHolder

import scala.collection.JavaConversions._
import scala.collection.JavaConverters._

class ProxiedAuthSpringProvider extends AuthorizationsProvider with Logging {

  private val NoAuths = new Authorizations()
  logger.info(s"Created new ${classOf[ProxiedAuthSpringProvider].getName} auths provider")

  override def getAuthorizations: Authorizations =
    Option(SecurityContextHolder.getContext.getAuthentication)
      .map { auth =>
        val user = auth.getPrincipal match {
          case s: String             => s
          case x                     => throw new IllegalArgumentException(s"Invalid spring security principal: $x")
        }

        // Rely on ProxyAuthHeaderFilter setting creds correctly as a java.util.List[String]
        logger.trace("Spring Credentials: " + auth.getCredentials)
        logger.trace("Spring Authorities: " + auth.getAuthorities.mkString(","))
        val userCreds: Seq[String] = Option(auth.getCredentials)
          .map {
            case lst if classOf[java.util.List[String]].isAssignableFrom(lst.getClass) => lst.asInstanceOf[java.util.List[String]].asScala
            case x: String =>
              logger.warn(s"Invalid authorizations...expected java.util.List[String] $x")
              List.empty[String]
          }.getOrElse(Seq.empty[String])

        logger.debug(s"Auths for $user set to ${userCreds.mkString(",")}")
        new Authorizations(userCreds.map(_.getBytes))
      }.getOrElse{
        logger.debug("No spring auth object found...no auths set")
        NoAuths
      }

  override def configure(params: util.Map[String, Serializable]): Unit = {
    // Not yet...
  }
}
