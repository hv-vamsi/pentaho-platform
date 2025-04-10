package org.pentaho.platform.plugin.services.security.userrole.oauth;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.pentaho.platform.api.engine.security.IAuthenticationRoleMapper;
import org.pentaho.platform.api.engine.security.userroledao.IPentahoRole;
import org.pentaho.platform.api.engine.security.userroledao.IPentahoUser;
import org.pentaho.platform.api.engine.security.userroledao.IUserRoleDao;
import org.pentaho.platform.api.mt.ITenant;
import org.pentaho.platform.security.userroledao.PentahoOAuthUser;
import org.pentaho.platform.security.userroledao.PentahoRole;
import org.pentaho.platform.security.userroledao.PentahoUser;
import org.pentaho.platform.util.oauth.PentahoOAuthUtility;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

@RunWith( MockitoJUnitRunner.class )
public class PentahoOAuthUserRoleServiceTest {

  @Mock
  IUserRoleDao userRoleDao;

  @Mock
  IAuthenticationRoleMapper roleMapper;

  @Mock
  ITenant tenant;

  @Test
  public void testGetAllRoles() {
    List<String> systemRoles = new ArrayList<>();
    systemRoles.add( "Administrator" );

    List<String> extraRoles = new ArrayList<>();
    extraRoles.add("Authenticated" );

    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao,
            roleMapper, systemRoles, extraRoles );

    List<IPentahoRole> pentahoRoles = new ArrayList<>();
    pentahoRoles.add( new PentahoRole( "Administrator" ) );
    when( userRoleDao.getRoles() ).thenReturn( pentahoRoles );

    Assert.assertTrue( pentahoOAuthUserRoleService.getAllRoles().containsAll( List.of( "Administrator", "Authenticated" ) ) );
  }

  @Test
  public void testGetAllRolesInTenant() {
    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao,
            roleMapper, Collections.emptyList(), Collections.emptyList() );

    when( userRoleDao.getRoles( null ) ).thenReturn( Collections.emptyList() );

    pentahoOAuthUserRoleService.getAllRoles( null );

    verify( userRoleDao, times( 1 ) ).getRoles( any() );
  }

  @Test
  public void testGetAllUsers() {
    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao,
            roleMapper, Collections.emptyList(), Collections.emptyList() );

    List<IPentahoUser> pentahoUsers = new ArrayList<>();
    pentahoUsers.add( new PentahoOAuthUser( new PentahoUser( "test" ), "", "" ) );
    when( userRoleDao.getUsers() ).thenReturn( pentahoUsers );

    Assert.assertEquals( "test", pentahoOAuthUserRoleService.getAllUsers().get( 0 ) );
  }

  @Test
  public void testGetAllUsersInTenant() {
    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao,
            roleMapper, Collections.emptyList(), Collections.emptyList() );

    when( userRoleDao.getUsers( null ) ).thenReturn( Collections.emptyList() );

    pentahoOAuthUserRoleService.getAllUsers( null );

    verify( userRoleDao, times( 1 ) ).getUsers( any() );
  }

  @Test
  public void testRolesForNullUser() {
    Authentication authentication = mock( OAuth2AuthenticationToken.class );
    SecurityContext securityContext = mock( SecurityContext.class );
    when( securityContext.getAuthentication() ).thenReturn( authentication );

    try ( MockedStatic<SecurityContextHolder> mockedSecurityContextHolder = mockStatic( SecurityContextHolder.class ) ) {
      mockedSecurityContextHolder.when(SecurityContextHolder::getContext).thenReturn(securityContext);

      PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService(userRoleDao,
              roleMapper, Collections.emptyList(), Collections.emptyList());

      Assert.assertTrue(pentahoOAuthUserRoleService.getRolesForUser(null, "admin")
              .containsAll(List.of("Administrator", "Authenticated")));
    }
  }

  @Test
  public void testRolesForNullAuthoritiesAndRolesUser() {
    Authentication authentication = mock(OAuth2AuthenticationToken.class);
    DefaultOidcUser defaultOidcUser = mock(DefaultOidcUser.class);

    SecurityContext securityContext = mock(SecurityContext.class);

    when(securityContext.getAuthentication()).thenReturn(authentication);

    try (MockedStatic<SecurityContextHolder> mockedSecurityContextHolder = mockStatic(SecurityContextHolder.class)) {
      mockedSecurityContextHolder.when(SecurityContextHolder::getContext).thenReturn(securityContext);

      when(authentication.getPrincipal()).thenReturn(defaultOidcUser);

      PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService(userRoleDao,
              roleMapper, Collections.emptyList(), Collections.emptyList());

      Assert.assertFalse(pentahoOAuthUserRoleService.getRolesForUser(null, "admin")
              .containsAll(List.of("Administrator", "Authenticated")));
    }
  }

  @Test
  public void testRolesForGenericUser() {
    SecurityContext securityContext = mock( SecurityContext.class );

    try ( MockedStatic<SecurityContextHolder> mockedSecurityContextHolder = mockStatic( SecurityContextHolder.class ) ) {
      mockedSecurityContextHolder.when(SecurityContextHolder::getContext).thenReturn(securityContext);
    }

    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao,
            roleMapper, Collections.emptyList(), Collections.emptyList() );

    Assert.assertTrue( pentahoOAuthUserRoleService.getRolesForUser( null, "admin" )
            .containsAll( List.of( "Administrator", "Authenticated" ) ) );
  }

  @Test
  public void testRolesForOAuthUser() {
    Authentication authentication = mock( OAuth2AuthenticationToken.class );
    DefaultOidcUser defaultOidcUser = mock( DefaultOidcUser.class );

    SecurityContext securityContext = mock( SecurityContext.class );

    when( securityContext.getAuthentication() ).thenReturn( authentication );

    try ( MockedStatic<SecurityContextHolder> mockedSecurityContextHolder = mockStatic( SecurityContextHolder.class ) ) {
      mockedSecurityContextHolder.when(SecurityContextHolder::getContext).thenReturn(securityContext);
      when( authentication.getPrincipal() ).thenReturn( defaultOidcUser );

      List oauthAuthorities = List.of( new SimpleGrantedAuthority( "Administrator" ), new SimpleGrantedAuthority( "Authenticated" ) );

      when( authentication.getAuthorities() ).thenReturn( oauthAuthorities );
      when( defaultOidcUser.getAttribute( "roles" ) ).thenReturn( List.of( "Administrator" ) );
      when( roleMapper.toPentahoRole( ( any() ) ) ).thenAnswer( invocation -> invocation.getArgument( 0 ) );

      PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao,
              roleMapper, Collections.emptyList(), Collections.emptyList() );

      Assert.assertTrue( pentahoOAuthUserRoleService.getRolesForUser( null, "admin" )
              .containsAll( List.of( "Administrator", "Authenticated" ) ) );
    }
  }


  @Test
  public void testGetUsersInRole() {
    when( userRoleDao.getRole( null, "Administrator" ) ).thenReturn( new PentahoRole( "Administrator" ) );
    when( userRoleDao.getRoleMembers( null, "Administrator" ) )
            .thenReturn( List.of ( new PentahoOAuthUser( new PentahoUser( "test" ), "", "" ) ) );

    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao, roleMapper,
            Collections.emptyList(), Collections.emptyList() );

    pentahoOAuthUserRoleService.getUsersInRole( null, "Administrator" );

    verify( userRoleDao, times( 1 ) ).getRole( any(), any() );
    verify( userRoleDao, times( 1 ) ).getRoleMembers( any(), any() );
  }

  @Test
  public void testGetUsersInRoleForTenant() {
    when( userRoleDao.getRole( tenant, "Administrator" ) ).thenReturn( new PentahoRole( "Administrator" ) );
    when( userRoleDao.getRoleMembers( tenant, "Administrator" ) )
            .thenReturn( List.of ( new PentahoOAuthUser( new PentahoUser( "test" ), "", "" ) ) );

    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao, roleMapper,
            Collections.emptyList(), Collections.emptyList() );

    pentahoOAuthUserRoleService.getUsersInRole( tenant, "Administrator" );

    verify( userRoleDao, times( 1 ) ).getRole( any(), any() );
    verify( userRoleDao, times( 1 ) ).getRoleMembers( any(), any() );
  }

  @Test
  public void testGetUsersInRoleForNoRole() {
    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao, roleMapper,
            Collections.emptyList(), Collections.emptyList() );

    pentahoOAuthUserRoleService.getUsersInRole( null, null );

    verify( userRoleDao, times( 1 ) ).getRole( any(), any() );
  }

  @Test
  public void testSetUserRoleDao() {
    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService();
    pentahoOAuthUserRoleService.setUserRoleDao( userRoleDao );

    Assert.assertEquals(userRoleDao, pentahoOAuthUserRoleService.getUserRoleDao());
  }

  @Test
  public void testSetSystemRoles() {
    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService();
    Assert.assertNull( pentahoOAuthUserRoleService.getSystemRoles() );
  }

  @Test
  public void testIsNewUser() {
    when( userRoleDao.getUser( tenant, "admin" ) ).thenReturn( new PentahoUser( "admin" ) );

    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao, roleMapper,
            Collections.emptyList(), Collections.emptyList() );
    Assert.assertFalse( pentahoOAuthUserRoleService.isNewUser( tenant, "admin" ) );
  }

  @Test
  public void testCreateUser() {
    DefaultOidcUser defaultOidcUser = mock( DefaultOidcUser.class );

    List oauthAuthorities = new ArrayList<>();
    oauthAuthorities.add( new SimpleGrantedAuthority("Administrator") );
    oauthAuthorities.add( new SimpleGrantedAuthority("Authenticated") );

    when( defaultOidcUser.getAuthorities() ).thenReturn( oauthAuthorities );

    // Create OAuth2AuthenticationToken using real data (you can mock the other parameters if needed)
    OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(
            defaultOidcUser,
            defaultOidcUser.getAuthorities(),
            "azure"
    );

    when( oAuth2AuthenticationToken.getName() ).thenReturn( "admin" );

    MockedStatic<PentahoOAuthUtility> pentahoOAuthUtilityMockedStatic = Mockito.mockStatic( PentahoOAuthUtility.class );
    pentahoOAuthUtilityMockedStatic.when( () -> PentahoOAuthUtility.getUserNameAttribute( any() ) ).thenReturn( "" );

    PentahoOAuthUserRoleService pentahoOAuthUserRoleService = new PentahoOAuthUserRoleService( userRoleDao, roleMapper,
            Collections.emptyList(), Collections.emptyList() );
    pentahoOAuthUserRoleService.createUser( oAuth2AuthenticationToken );

    when( oAuth2AuthenticationToken.getPrincipal().getAttribute( "oid" ) ).thenReturn( "admin" );
    pentahoOAuthUserRoleService.createUser( oAuth2AuthenticationToken );

    when( oAuth2AuthenticationToken.getPrincipal().getAttribute( "oid" ) ).thenReturn( null );
    when( oAuth2AuthenticationToken.getPrincipal().getAttribute( "user_id" ) ).thenReturn( "admin" );
    pentahoOAuthUserRoleService.createUser( oAuth2AuthenticationToken );

    when( oAuth2AuthenticationToken.getPrincipal().getAttribute( "oid" ) ).thenReturn( null );
    when( oAuth2AuthenticationToken.getPrincipal().getAttribute( "user_id" ) ).thenReturn( null );
    when( oAuth2AuthenticationToken.getPrincipal().getAttribute( "sub" ) ).thenReturn( "admin" );
    when( userRoleDao.getUser( any(), any() ) ).thenReturn( mock( IPentahoUser.class ) );
    pentahoOAuthUserRoleService.createUser( oAuth2AuthenticationToken );

    verify(userRoleDao, times(3)).createOAuthUser(any(), any(), any(), any(), any(), any(), any());
  }

}
