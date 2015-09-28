package geomesa.sec.gs.filter

import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig
import org.geoserver.security.web.auth.AuthenticationFilterPanelInfo

class ProxiedAuthHeaderFilterPanelInfo extends AuthenticationFilterPanelInfo[RequestHeaderAuthenticationFilterConfig, ProxiedAuthHeaderFilterPanel] {

  setComponentClass(classOf[ProxiedAuthHeaderFilterPanel])
  setServiceClass(classOf[ProxiedAuthHeaderFilter])
  setServiceConfigClass(classOf[RequestHeaderAuthenticationFilterConfig])

}
