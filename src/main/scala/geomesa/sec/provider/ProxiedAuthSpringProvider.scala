package geomesa.sec.provider

import java.io.Serializable
import java.util

import com.typesafe.scalalogging.slf4j.Logging
import geomesa.sec.gs.filter.ProxiedUser
import geomesa.sec.provider.ProxiedAuthSpringProvider.NoAuths
import org.apache.accumulo.core.security.Authorizations
import org.locationtech.geomesa.security.AuthorizationsProvider
import org.springframework.security.core.context.SecurityContextHolder

import scala.collection.JavaConversions._

class ProxiedAuthSpringProvider extends AuthorizationsProvider with Logging {

  override def getAuthorizations: Authorizations =
    Option(SecurityContextHolder.getContext.getAuthentication)
      .map { auth =>
        val user = auth.getPrincipal match {
          case u: ProxiedUser => u
          case x              => throw new IllegalArgumentException(s"Invalid spring security principal: $x")
        }
        logger.debug(s"ProxiedUser: $user")
        new Authorizations(user.visibilites.map(_.getBytes))
      }.getOrElse{
        logger.debug("No spring auth object found...no auths set")
        NoAuths
      }

  override def configure(params: util.Map[String, Serializable]): Unit = {}
}

object ProxiedAuthSpringProvider {
  private val NoAuths = new Authorizations()
}