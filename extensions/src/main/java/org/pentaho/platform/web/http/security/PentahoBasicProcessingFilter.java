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


package org.pentaho.platform.web.http.security;

import com.google.common.annotations.VisibleForTesting;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.SessionCookieConfig;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

/**
 * This class's sole purpose is to defeat the persistence of Basic-Auth credentials in the browser.
 * The mechanism used to accomplish this is to detect an expired (invalid) HttpSession from the client.
 * <p/>
 * If the first request after a session becomes invalid is a Basic-Auth request, we automatically deny, forcing
 * reauthentication.
 * <p/>
 * The second path is if the first request after session invalidation is not a basic-auth (user manually logged out and
 * was presented with the login page), we drop a cookie in the response noting the event. The next request with
 * Basic-Auth and a valid HttpSession checks for this cookie and if present, forces reauthentication.
 * <p/>
 * <p/>
 * User: nbaker Date: 8/15/13
 */
public class PentahoBasicProcessingFilter extends BasicAuthenticationFilter implements ApplicationEventPublisherAware {

  private static final Log logger = LogFactory.getLog( PentahoBasicProcessingFilter.class );

  @VisibleForTesting
  static final String SESSION_FLUSHED_COOKIE_NAME = "session-flushed";

  @VisibleForTesting
  static final String SESSION_ID_COOKIE_NAME = "JSESSIONID";


  private ApplicationEventPublisher applicationEventPublisher;

  /**
   * Cached value of the {@code jwt-enabled} system setting from {@code pentaho.xml}.
   * Lazily resolved on the first request via {@link #isJwtModeEnabled()}.
   * {@code null} means "not yet resolved".
   */
  private volatile Boolean jwtModeEnabled = null;

  public PentahoBasicProcessingFilter( AuthenticationManager authenticationManager,
                                       AuthenticationEntryPoint authenticationEntryPoint ) {
    super( authenticationManager, authenticationEntryPoint );
  }

  public void setApplicationEventPublisher( ApplicationEventPublisher applicationEventPublisher ) {
    this.applicationEventPublisher = applicationEventPublisher;
  }

  @Override
  public void doFilterInternal( HttpServletRequest request, HttpServletResponse response, FilterChain chain )
    throws IOException, ServletException {

    // If the request already carries a Bearer token (JWT), skip Basic-Auth processing entirely.
    // JWT requests are stateless and should not interact with session/cookie-based logic.
    String authHeader = request.getHeader( "Authorization" );
    if ( authHeader != null && authHeader.startsWith( "Bearer " ) ) {
      chain.doFilter( request, response );
      return;
    }

    // In JWT mode ALL requests are stateless — there are no HttpSessions, so the
    // session-flushed detection logic (expired JSESSIONID → force re-auth) is irrelevant.
    // Skip directly to Basic-Auth processing without any session/cookie side-effects.
    if ( isJwtModeEnabled() ) {
      doFilterInternalSuper( request, response, chain );
      return;
    }

    if ( request.getRequestedSessionId() != null && !request.isRequestedSessionIdValid() ) {
      // Expired session detected.

      if ( isBasicAuthRequest( request ) ) {
        // Session is expired and a Basic-Auth request is coming in.

        // Clear any session-flushed cookie.
        clearSessionFlushedCookie( request, response );

        // Ignore provided credentials, and force the prompt for (new) credentials.
        getAuthenticationEntryPoint()
          .commence( request, response, new BadCredentialsException( "Clearing Basic-Auth" ) );
        return;
      }

      // Check that this definitely is a browser with an expired session.
      boolean hasExpiredSessionCookie = Arrays.stream( request.getCookies() )
        .anyMatch( cookie -> SESSION_ID_COOKIE_NAME.equals( cookie.getName() ) );

      if ( hasExpiredSessionCookie ) {
        // Session is expired but this request does not include basic-auth,
        // drop a cookie to keep track that session had expired.
        response.addCookie( createSessionFlushedCookie( request ) );
      }
    } else if ( isBasicAuthRequest( request ) && SecurityContextHolder.getContext().getAuthentication() == null ) {
      // Session is valid, not authenticated, and Basic-auth is supplied.
      // Check to see if the session-flushed cookie we created is present, and, if so, force reauthentication for
      // the Pentaho realm.
      if ( clearSessionFlushedCookie( request, response ) ) {
        getAuthenticationEntryPoint()
          .commence( request, response, new BadCredentialsException( "Clearing Basic-Auth" ) );
        return;
      }
    }

    doFilterInternalSuper( request, response, chain );
  }

  @VisibleForTesting
  void doFilterInternalSuper( HttpServletRequest request, HttpServletResponse response, FilterChain chain )
    throws IOException, ServletException {
    super.doFilterInternal( request, response, chain );
  }

  @Override
  protected void onSuccessfulAuthentication( HttpServletRequest request, HttpServletResponse response,
                                             Authentication authResult ) throws IOException {
    super.onSuccessfulAuthentication( request, response, authResult );

    // In JWT mode, do NOT touch HttpSession — sessions are not used and calling
    // request.getSession() would trigger Tomcat to create one (and set JSESSIONID).
    if ( !isJwtModeEnabled() ) {
      request.getSession().setAttribute( "BasicAuth", "true" );
    }

    if ( applicationEventPublisher != null ) {
      applicationEventPublisher.publishEvent( new AuthenticationSuccessEvent( authResult ) );
    }
  }

  protected boolean isBasicAuthRequest( @NonNull HttpServletRequest request ) {
    String header = request.getHeader( "Authorization" );
    return header != null && header.indexOf( "Basic" ) == 0;
  }

  @NonNull
  protected Cookie createSessionFlushedCookie( @NonNull HttpServletRequest request ) {
    Cookie cookie = new Cookie( SESSION_FLUSHED_COOKIE_NAME, "true" );
    // maxAge: -1 means the cookie is cleared when the web-browser session ends.
    configureSessionFlushedCookie( cookie, request, -1 );
    return cookie;
  }

  protected static void configureSessionFlushedCookie( @NonNull Cookie cookie,
                                                     @NonNull HttpServletRequest request,
                                                     int maxAge ) {
    SessionCookieConfig sessionCookieConfig = request.getServletContext().getSessionCookieConfig();
    cookie.setPath( request.getContextPath() != null ? request.getContextPath() : "/" );
    cookie.setHttpOnly( sessionCookieConfig.isHttpOnly() );
    cookie.setSecure( sessionCookieConfig.isSecure() );
    cookie.setMaxAge( maxAge );
  }

  // Used by PentahoBasicAuthenticationEntryPoint
  static boolean clearSessionFlushedCookie( @NonNull HttpServletRequest request,
                                            @NonNull HttpServletResponse response ) {
    Cookie[] cookies = request.getCookies();
    if ( cookies != null ) {
      for ( Cookie cookie : cookies ) {
        if ( SESSION_FLUSHED_COOKIE_NAME.equals( cookie.getName() ) ) {
          // maxAge: 0 causes the browser to remove the cookie.
          configureSessionFlushedCookie( cookie, request, 0 );
          response.addCookie( cookie );
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Returns whether JWT stateless authentication is the primary authentication mode.
   * When {@code true}, session-flushed cookie logic and HttpSession creation are skipped.
   */
  @VisibleForTesting
  boolean isJwtModeEnabled() {
    if ( jwtModeEnabled == null ) {
      String setting = PentahoSystem.getSystemSetting( "jwt-enabled", "true" );
      jwtModeEnabled = Boolean.parseBoolean( setting );
      if ( logger.isDebugEnabled() ) {
        logger.debug( "jwt-enabled system setting resolved to: " + jwtModeEnabled );
      }
    }
    return jwtModeEnabled;
  }
}
