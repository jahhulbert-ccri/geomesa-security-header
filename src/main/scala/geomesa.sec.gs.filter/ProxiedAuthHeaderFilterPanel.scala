package geomesa.sec.gs.filter

import org.apache.wicket.markup.html.form.TextField
import org.apache.wicket.model.IModel
import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig
import org.geoserver.security.web.auth.PreAuthenticatedUserNameFilterPanel

class ProxiedAuthHeaderFilterPanel(id: String, model: IModel[RequestHeaderAuthenticationFilterConfig])
  extends PreAuthenticatedUserNameFilterPanel[RequestHeaderAuthenticationFilterConfig](id, model) {

  add(new TextField("principalHeaderAttribute").setRequired(true))

}
