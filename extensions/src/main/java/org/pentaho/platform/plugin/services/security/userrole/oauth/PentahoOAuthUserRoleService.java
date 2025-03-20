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

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.pentaho.platform.api.engine.IUserRoleListService;
import org.pentaho.platform.api.engine.security.IAuthenticationRoleMapper;
import org.pentaho.platform.api.engine.security.userroledao.IPentahoRole;
import org.pentaho.platform.api.engine.security.userroledao.IPentahoUser;
import org.pentaho.platform.api.engine.security.userroledao.IUserRoleDao;
import org.pentaho.platform.api.engine.security.userroledao.UncategorizedUserRoleDaoException;
import org.pentaho.platform.api.mt.ITenant;
import org.pentaho.platform.engine.security.SecurityHelper;
import org.pentaho.platform.repository2.unified.jcr.JcrTenantUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;

@Service
public class PentahoOAuthUserRoleService implements IUserRoleListService {

  private OAuth2AuthorizedClientService authorizedClientService;

  private IUserRoleDao userRoleDao;

  private IAuthenticationRoleMapper roleMapper;

  private String roleHolderKey;

  private List<String> systemRoles;
  private List<String> extraRoles;
  private String adminRole;


  public PentahoOAuthUserRoleService() {

  }

  public PentahoOAuthUserRoleService( OAuth2AuthorizedClientService authorizedClientService,
                                      IUserRoleDao userRoleDao,
                                      IAuthenticationRoleMapper roleMapper,
                                      String roleHolderKey,
                                      List<String> systemRoles,
                                      List<String> extraRoles,
                                      final String adminRole) {
    this.authorizedClientService = authorizedClientService;
    this.userRoleDao = userRoleDao;
    this.roleMapper = roleMapper;
    this.roleHolderKey = roleHolderKey;
    this.systemRoles = systemRoles;
    this.extraRoles = extraRoles;
    this.adminRole = adminRole;
  }

  public String getRoleHolderKey() {
    return roleHolderKey;
  }

  private List<String> getAllRoles( List<IPentahoRole> roles ) {
    List<String> auths = new ArrayList<>( roles.size() );

    for ( IPentahoRole role : roles ) {
      auths.add( role.getName() );
    }
    // We will not allow user to update permission for Administrator
    if ( auths.contains( adminRole ) ) {
      auths.remove( adminRole );
    }
    // Add extra roles to the list of roles if it does not already have it
    for ( String extraRole : extraRoles ) {
      if ( !auths.contains( extraRole ) ) {
        auths.add( extraRole );
      }
    }

    return auths;
  }

  @Override
  public List<String> getAllRoles() {
    return getAllRoles( userRoleDao.getRoles() );
  }

  @Override
  public List<String> getAllRoles( ITenant tenant ) {
    return getAllRoles( userRoleDao.getRoles( tenant ) );
  }

  private List<String> getAllUsers( List<IPentahoUser> users ) {
    List<String> usernames = new ArrayList<>();

    for ( IPentahoUser user : users ) {
      usernames.add( user.getUsername() );
    }

    return usernames;
  }

  @Override
  public List<String> getAllUsers() {
    return getAllUsers( userRoleDao.getUsers() );
  }

  @Override
  public List<String> getAllUsers( ITenant tenant ) {
    return getAllUsers( userRoleDao.getUsers( tenant ) );
  }

  @Override
  public List<String> getRolesForUser( ITenant tenant, String username ) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if ( authentication instanceof OAuth2AuthenticationToken ) {
      DefaultOidcUser defaultOidcUser = (DefaultOidcUser) authentication.getPrincipal();
      if ( Objects.nonNull( defaultOidcUser ) ) {
        List<String> pentahoAuthorities = new ArrayList<>();

        if ( StringUtils.equals( roleHolderKey, "authorities" ) ) {
          Collection<? extends GrantedAuthority> oauthAuthorities = authentication.getAuthorities();
          if ( CollectionUtils.isNotEmpty( oauthAuthorities ) ) {
            pentahoAuthorities.add( "Authenticated" );
            oauthAuthorities.forEach( authority ->
                    pentahoAuthorities.add( roleMapper.toPentahoRole( authority.getAuthority() ) ) );
          }
        } else if ( StringUtils.equals( roleHolderKey, "roles" ) ) {
          List<String> oauthRoles = defaultOidcUser.getAttribute( "roles" );
          if ( CollectionUtils.isNotEmpty( oauthRoles ) ) {
            pentahoAuthorities.add( "Authenticated" );
            oauthRoles.forEach( role -> pentahoAuthorities.add( roleMapper.toPentahoRole( role ) ) );
          }
        }

        return pentahoAuthorities;
      }
    }
    // This is not correct. But, it is given that execution will reach here only after idp redirects back with
    // successful login. Hence, doing it.
    return List.of( "Administrator", "Authenticated" );
  }

  public List<String> getUsersInRole( ITenant tenant, IPentahoRole role, String roleName ) {
    if ( role == null ) {
      return Collections.emptyList();
    }
    List<IPentahoUser> users = null;
    List<String> usernames = new ArrayList<String>();
    if ( tenant == null ) {
      users = userRoleDao.getRoleMembers( null, roleName );
    } else {
      users = userRoleDao.getRoleMembers( tenant, roleName );
    }

    for ( IPentahoUser user : users ) {
      usernames.add( user.getUsername() );
    }

    return usernames;
  }

  @Override
  public List<String> getUsersInRole( ITenant tenant, String roleName ) {
    return getUsersInRole( tenant, userRoleDao.getRole( tenant, roleName ), roleName );
  }

  public void setUserRoleDao( IUserRoleDao userRoleDao ) {
    this.userRoleDao = userRoleDao;
  }

  @Override
  public List<String> getSystemRoles() {
    return systemRoles;
  }

  public void createUser( OAuth2AuthenticationToken authentication ) {
    ITenant tenant = JcrTenantUtils.getTenant();
    String username = authentication.getName();

    List<String> roles = getRolesForUser( tenant, username );
    roles.remove( "Authenticated" );
    String[] userRoles = roles.toArray( new String[0] );

    String registrationId = authentication.getAuthorizedClientRegistrationId();
    String userId = authentication.getPrincipal().getAttribute( "oid" );

    if ( StringUtils.isBlank( userId ) ) {
      userId = authentication.getPrincipal().getAttribute( "user_id" );
    }

    if ( StringUtils.isBlank( userId ) ) {
      userId = authentication.getPrincipal().getAttribute( "sub" );
    }

    if ( StringUtils.isBlank( userId ) ) {
      //TODO fetch from security properties based on registrationId and tenantId
    }

    if ( isNewUser( tenant, username ) ) {
      userRoleDao.createOAuthUser( tenant, username,"", "", userRoles, registrationId, userId );
    }
  }

  public boolean isNewUser( ITenant tenant, String name ) throws UncategorizedUserRoleDaoException {
    return Objects.isNull( userRoleDao.getUser( tenant, name ) );
  }

  private String getAccessToken() {

    // Retrieve the OAuth2AuthenticationToken from the SecurityContext
    OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

    if ( authenticationToken == null ) {
      return "User is not authenticated";
    }

    // Retrieve the OAuth2AuthorizedClient associated with the user
    OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
            authenticationToken.getAuthorizedClientRegistrationId(),
            authenticationToken.getName()
    );

    // Check if the authorizedClient is null
    if ( authorizedClient == null ) {
      return "No authorized client found for the user";
    }

    // Retrieve the access token from the OAuth2AuthorizedClient
    return authorizedClient.getAccessToken().getTokenValue();
  }

}
