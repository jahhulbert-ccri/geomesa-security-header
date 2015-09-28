package geomesa.sec.gs.filter

import org.geoserver.security.config.SecurityNamedServiceConfig
import org.geoserver.security.filter.{GeoServerRequestHeaderAuthenticationProvider, GeoServerSecurityFilter}

class ProxiedAuthHeaderProvider extends GeoServerRequestHeaderAuthenticationProvider {

  override def getFilterClass: Class[_ <: GeoServerSecurityFilter] = classOf[ProxiedAuthHeaderFilter]

  override def createFilter(config: SecurityNamedServiceConfig) = new ProxiedAuthHeaderFilter
}
