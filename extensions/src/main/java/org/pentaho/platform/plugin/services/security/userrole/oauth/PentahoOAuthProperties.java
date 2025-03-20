package org.pentaho.platform.plugin.services.security.userrole.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.pentaho.platform.api.engine.IConfiguration;
import org.pentaho.platform.api.engine.ISystemConfig;
import org.pentaho.platform.engine.core.system.PentahoSystem;

import java.io.IOException;
import java.util.Objects;
import java.util.Properties;

public class PentahoOAuthProperties {

  private static final Log logger = LogFactory.getLog( PentahoOAuthProperties.class );

  Properties properties;

  private static ISystemConfig systemConfig = PentahoSystem.get( ISystemConfig.class );

  public String getValue( String key ) {

    if ( Objects.isNull( properties ) ) {
      IConfiguration config = systemConfig.getConfiguration( "oauth" );

      try {
        properties = config.getProperties();
      } catch ( IOException e ) {
        properties = new Properties();
        logger.error( e );
      }
    }

    return properties.getProperty( key );
  }

}
