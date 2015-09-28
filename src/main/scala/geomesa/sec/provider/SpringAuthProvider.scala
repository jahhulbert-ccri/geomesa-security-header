package geomesa.sec.provider

import java.io.Serializable
import java.util

import com.typesafe.scalalogging.slf4j.Logging
import org.apache.accumulo.core.security.Authorizations
import org.locationtech.geomesa.security.AuthorizationsProvider
import org.springframework.security.core.context.SecurityContextHolder

import scala.collection.JavaConversions._

class SpringAuthProvider extends AuthorizationsProvider with Logging {

  logger.info(s"Created new ${classOf[SpringAuthProvider].getName} auths provider")

  override def getAuthorizations: Authorizations = {
    val auth = SecurityContextHolder.getContext.getAuthentication
    val principal = auth.getPrincipal.asInstanceOf[String]
    val springCreds = auth.getCredentials.asInstanceOf[java.util.List[String]] // accumulo authorizations as a java.util.List[String]
    logger.debug(s"Setting scan creditials for user $principal to ${springCreds.mkString(",")}")
    return new Authorizations(springCreds.map(_.getBytes))
  }

  override def configure(params: util.Map[String, Serializable]): Unit = {
    // Not yet...
  }
}
