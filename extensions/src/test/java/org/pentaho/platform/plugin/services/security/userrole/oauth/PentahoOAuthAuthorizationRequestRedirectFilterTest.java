package org.pentaho.platform.plugin.services.security.userrole.oauth;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.pentaho.platform.util.oauth.PentahoOAuthUtility;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith( MockitoJUnitRunner.class )
public class PentahoOAuthAuthorizationRequestRedirectFilterTest {

  @Mock
  private ClientRegistrationRepository clientRegistrationRepository;

  @Mock
  private OAuth2AuthorizationRequestResolver authorizationRequestResolver;

  @Mock
  private HttpServletRequest servletRequest;

  @Mock
  private HttpServletResponse servletResponse;

  @Mock
  private FilterChain filterChain;

  @Test
  public void proceedsWithSuperFilterWhenOAuthEnabledAndNotUserNamePasswordAuthentication() throws Exception {
    when(PentahoOAuthUtility.isOAuthEnabled()).thenReturn(true);
    when(PentahoOAuthUtility.isUserNamePasswordAuthentication(servletRequest)).thenReturn(false);

    PentahoOAuthAuthorizationRequestRedirectFilter filter = new PentahoOAuthAuthorizationRequestRedirectFilter(clientRegistrationRepository);
    filter.doFilterInternal(servletRequest, servletResponse, filterChain);

    verify(filterChain).doFilter(servletRequest, servletResponse);
  }

  @Test
  public void skipsSuperFilterWhenOAuthDisabled() throws Exception {
    when(PentahoOAuthUtility.isOAuthEnabled()).thenReturn(false);

    PentahoOAuthAuthorizationRequestRedirectFilter filter = new PentahoOAuthAuthorizationRequestRedirectFilter(clientRegistrationRepository);
    filter.doFilterInternal(servletRequest, servletResponse, filterChain);

    verify(filterChain).doFilter(servletRequest, servletResponse);
  }

  @Test
  public void skipsSuperFilterWhenUserNamePasswordAuthentication() throws Exception {
    when(PentahoOAuthUtility.isOAuthEnabled()).thenReturn(true);
    when(PentahoOAuthUtility.isUserNamePasswordAuthentication(servletRequest)).thenReturn(true);

    PentahoOAuthAuthorizationRequestRedirectFilter filter = new PentahoOAuthAuthorizationRequestRedirectFilter(clientRegistrationRepository);
    filter.doFilterInternal(servletRequest, servletResponse, filterChain);

    verify(filterChain).doFilter(servletRequest, servletResponse);
  }

  @Test
  public void proceedsWithSuperFilterWhenUsingAuthorizationRequestBaseUriConstructor() throws Exception {
    when(PentahoOAuthUtility.isOAuthEnabled()).thenReturn(true);
    when(PentahoOAuthUtility.isUserNamePasswordAuthentication(servletRequest)).thenReturn(false);

    PentahoOAuthAuthorizationRequestRedirectFilter filter = new PentahoOAuthAuthorizationRequestRedirectFilter(clientRegistrationRepository, "/custom-uri");
    filter.doFilterInternal(servletRequest, servletResponse, filterChain);

    verify(filterChain).doFilter(servletRequest, servletResponse);
  }

  @Test
  public void proceedsWithSuperFilterWhenUsingAuthorizationRequestResolverConstructor() throws Exception {
    when(PentahoOAuthUtility.isOAuthEnabled()).thenReturn(true);
    when(PentahoOAuthUtility.isUserNamePasswordAuthentication(servletRequest)).thenReturn(false);

    PentahoOAuthAuthorizationRequestRedirectFilter filter = new PentahoOAuthAuthorizationRequestRedirectFilter(authorizationRequestResolver);
    filter.doFilterInternal(servletRequest, servletResponse, filterChain);

    verify(filterChain).doFilter(servletRequest, servletResponse);
  }
}