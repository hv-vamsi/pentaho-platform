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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.pentaho.platform.api.engine.security.IAuthenticationRoleMapper;
import org.pentaho.platform.api.engine.security.userroledao.IUserRoleDao;
import org.pentaho.platform.api.mt.ITenant;
import org.pentaho.platform.security.userroledao.PentahoOAuthUser;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class PentahoOAuthAzureHandler implements IPentahoOAuthHandler {

  IUserRoleDao userRoleDao;

  RestTemplate restTemplate;

  IAuthenticationRoleMapper oauthRoleMapper;

  PentahoOAuthProperties pentahoOAuthProperties;

  public PentahoOAuthAzureHandler( IUserRoleDao userRoleDao,
                                  RestTemplate restTemplate,
                                  IAuthenticationRoleMapper oauthRoleMapper,
                                  PentahoOAuthProperties pentahoOAuthProperties ) {
    this.userRoleDao = userRoleDao;
    this.restTemplate = restTemplate;
    this.oauthRoleMapper = oauthRoleMapper;
    this.pentahoOAuthProperties = pentahoOAuthProperties;
  }

  public String getClientCredentialsToken( String registrationId, boolean renewToken ) {
    var registrationToClientCredentialsToken = new HashMap<String, String>();
    String clientCredentialsToken = registrationToClientCredentialsToken.get( registrationId );

    if ( renewToken || StringUtils.isBlank( clientCredentialsToken ) ) {
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType( MediaType.APPLICATION_FORM_URLENCODED );

      MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
      map.add( "client_id", pentahoOAuthProperties.getValue( registrationId + ".client-id" ) );
      map.add( "client_secret", pentahoOAuthProperties.getValue( registrationId + ".client-secret" ) );
      map.add( "grant_type", "client_credentials" );
      map.add( "redirect_uri", pentahoOAuthProperties.getValue( registrationId + ".redirect-uri" ) );
      map.add( "scope", "https://graph.microsoft.com/.default" );

      HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

      String url = pentahoOAuthProperties.getValue( registrationId + ".token-uri" );
      ResponseEntity<Map> responseEntity = restTemplate.postForEntity( url, request, Map.class );
      clientCredentialsToken = (String) responseEntity.getBody().get( "access_token" );
      registrationToClientCredentialsToken.put( registrationId, clientCredentialsToken );
    }
    return clientCredentialsToken;
  }

  public Map<String, String> getAppRolesInIdp( String registrationId, String clientCredentialsToken, boolean retry ) {
    var registrationToAppRoles = new HashMap<String, Map<String, String>>();

    var appRoles = registrationToAppRoles.get( registrationId );
    if ( MapUtils.isEmpty( appRoles ) ) {
      try {
        var responseEntity = PentahoOAuthUtility.getInstance().getResponseEntity( registrationId + ".app-roles", clientCredentialsToken, "", retry, Map.class );

        if ( Objects.isNull( responseEntity ) ) {
          return appRoles;
        }
        // Extract the 'value' array from the response map
        List<Map<String, Object>> valueList = ( List<Map<String, Object>> ) responseEntity.getBody().get( "value" );

        // Map each item in the 'value' array to an Item object containing only id and desc
        appRoles = valueList.stream()
                .collect( Collectors.toMap( item -> (String) item.get( "id" ), item -> (String) item.get( "value" ) ) );
        registrationToAppRoles.put( registrationId, appRoles );
      } catch ( Exception e ) {
        if ( retry ) {
          this.getAppRolesInIdp( registrationId, this.getClientCredentialsToken( registrationId, true ), false );
        }
      }
    }

    return appRoles;
  }

  @Override
  public boolean isUserAccountEnabled( String registrationId, String clientCredentialsToken, String userId, boolean retry ) {
    ResponseEntity<Map> responseEntity = null;
    try {
      responseEntity = PentahoOAuthUtility.getInstance().getResponseEntity( registrationId + ".account-enabled", clientCredentialsToken, userId, retry, Map.class );
    } catch ( Exception e ) {
      if ( retry ) {
        this.isUserAccountEnabled( registrationId, this.getClientCredentialsToken( registrationId, true ), userId, false );
      }
    }
    return (Boolean) responseEntity.getBody().get( "accountEnabled" );
  }

  @Override
  public List<String> getAppRoleAssignmentsForUser( String registrationId, String clientCredentialsToken, String userId, boolean retry ) {
    List<Map<String, Object>> valueList = new ArrayList<>();
    try {
      var responseEntity = PentahoOAuthUtility.getInstance().getResponseEntity( registrationId + ".app-role-assignments", clientCredentialsToken, userId, retry, Map.class );
      if ( Objects.isNull( responseEntity ) ) {
        return Collections.EMPTY_LIST;
      }
      // Extract the 'value' array from the response map
      valueList = ( List<Map<String, Object>> ) responseEntity.getBody().get( "value" );
    } catch ( Exception e ) {
      this.getAppRoleAssignmentsForUser( registrationId, this.getClientCredentialsToken( registrationId, true ), userId, false );
    }

    // Map each item in the 'value' array to an Item object containing only id and desc
    return valueList.stream().map(item -> (String) item.get( "appRoleId" ) )
            .collect( Collectors.toList() );
  }

  @Override
  public void updatePentahoUser( ITenant tenant, String userName, String[] roles ) {
    userRoleDao.setUserRoles( tenant, userName, roles );
  }

  @Override
  public void performSyncForUser( PentahoOAuthUser pentahoUser ) {
    String registrationId = pentahoUser.getRegistrationId();

    String clientCredentialsToken = this.getClientCredentialsToken( registrationId, false );

    boolean isUserAccountEnabled = this.isUserAccountEnabled( registrationId, clientCredentialsToken, pentahoUser.getUserId(), true );
    if ( !isUserAccountEnabled ) {
      this.updatePentahoUser( pentahoUser.getTenant(), pentahoUser.getUsername(), new String[ 0 ] );
    }

    Map<String, String> pentahoOAuthAzureAppRoles = this.getAppRolesInIdp( registrationId, clientCredentialsToken, true );
    List<String> oauthRoleIds = this.getAppRoleAssignmentsForUser( registrationId, clientCredentialsToken, pentahoUser.getUserId(), true );

    String[] pentahoRoles = oauthRoleIds.stream()
            .map( pentahoOAuthAzureAppRoles::get )
            .filter( Objects::nonNull )
            .map( oauthRoleMapper::toPentahoRole )
            .toArray( String[]::new );

    this.updatePentahoUser( pentahoUser.getTenant(), pentahoUser.getUsername(), pentahoRoles );
  }

}
