/*! ******************************************************************************
 *
 * Pentaho
 *
 * Copyright (C) 2024 by Hitachi Vantara, LLC : http://www.pentaho.com
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file.
 *
 * Change Date: 2029-07-20
 ******************************************************************************/

package org.pentaho.platform.plugin.services.security.userrole.oauth;

import org.apache.commons.lang.StringUtils;
import org.pentaho.platform.api.engine.IConfiguration;
import org.pentaho.platform.api.engine.ISystemConfig;
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class PentahoOAuthUtility {

  RestTemplate restTemplate = new RestTemplate();

  PentahoOAuthProperties pentahoOAuthProperties = new PentahoOAuthProperties();

  private static ISystemConfig systemConfig = PentahoSystem.get( ISystemConfig.class );

  private static boolean isProviderOAuth = false;

  private static boolean isProviderDualAuth = false;

  private static PentahoOAuthUtility instance;

  // Private constructor to prevent instantiation from outside
  private PentahoOAuthUtility() {
  }

  // Public method to provide access to the single instance
  public static PentahoOAuthUtility getInstance() {
    if ( instance == null ) {
      instance = new PentahoOAuthUtility();
    }
    return instance;
  }

  public static boolean isOAuthEnabled() {

    IConfiguration config = systemConfig.getConfiguration( "security" );

    if ( !isProviderOAuth ) {
      String provider = null;
      try {
        provider = config.getProperties().getProperty( "provider" );
      } catch ( IOException e ) {
        isProviderOAuth = false;
      }
      isProviderOAuth = StringUtils.equals( provider, "oauth" );
      isProviderDualAuth = StringUtils.equals( provider, "dualauth" );
    }

    if ( !isProviderOAuth && isProviderDualAuth ) {
      config = systemConfig.getConfiguration( "applicationContext-pentaho-security-dualauth" );
      String provider1 = null;
      String provider2 = null;
      try {
        provider1 = config.getProperties().getProperty( "provider1" );
        provider2 = config.getProperties().getProperty( "provider2" );
      } catch ( IOException e ) {
        isProviderOAuth = false;
      }
      isProviderOAuth = StringUtils.equals( provider1, "oauth" ) || StringUtils.equals( provider2, "oauth" );
    }

    return isProviderOAuth;
  }

  public static boolean isUserNamePasswordAuthentication( HttpServletRequest httpServletRequest ) {
    return  "/pentaho/j_spring_security_check".equals( httpServletRequest.getRequestURI() ) ||
            SecurityContextHolder.getContext().getAuthentication() instanceof UsernamePasswordAuthenticationToken;
  }

  public static String getIdpByRegistrationId( String registrationId ) {
    IConfiguration config = systemConfig.getConfiguration( "oauth" );
    try {
      return config.getProperties().getProperty( registrationId + ".provider" );
    } catch ( IOException e ) {
      return null;
    }
  }

  public <T> ResponseEntity<T> getResponseEntity( String key,
                                                  String clientCredentialsToken,
                                                  String userId,
                                                  boolean retry,
                                                  Class<T> responseType ) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth( clientCredentialsToken );
    HttpEntity<String> request = new HttpEntity<>( headers );
    String url = pentahoOAuthProperties.getValue( key ).replace( "{userId}", userId );

    try {
      return restTemplate.exchange( url, HttpMethod.GET, request, responseType );
    } catch ( Exception e ) {
      if ( retry ) {
        throw e;
      }
    }
    return null;
  }

}
