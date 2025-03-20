package org.pentaho.platform.plugin.services.security.userrole.oauth;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.pentaho.platform.api.mt.ITenant;
import org.pentaho.platform.security.userroledao.PentahoOAuthUser;
import org.pentaho.platform.security.userroledao.PentahoUser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class PentahoOAuthUserTest {

  @Mock
  ITenant tenant;

  @Test
  public void getRegistrationId_shouldReturnCorrectValue() {
    PentahoUser pentahoUser = new PentahoUser( tenant, "username", "password", "description", true);
    PentahoOAuthUser oAuthUser = new PentahoOAuthUser(pentahoUser, "registrationId", "userId");

    assertEquals("registrationId", oAuthUser.getRegistrationId());
  }

  @Test
  public void setRegistrationId_shouldUpdateValue() {
    PentahoUser pentahoUser = new PentahoUser( tenant, "username", "password", "description", true);
    PentahoOAuthUser oAuthUser = new PentahoOAuthUser(pentahoUser, "registrationId", "userId");

    oAuthUser.setRegistrationId("newRegistrationId");

    assertEquals("newRegistrationId", oAuthUser.getRegistrationId());
  }

  @Test
  public void getUserId_shouldReturnCorrectValue() {
    PentahoUser pentahoUser = new PentahoUser( tenant, "username", "password", "description", true);
    PentahoOAuthUser oAuthUser = new PentahoOAuthUser(pentahoUser, "registrationId", "userId");

    assertEquals("userId", oAuthUser.getUserId());
  }

  @Test
  public void setUserId_shouldUpdateValue() {
    PentahoUser pentahoUser = new PentahoUser( tenant, "username", "password", "description", true);
    PentahoOAuthUser oAuthUser = new PentahoOAuthUser(pentahoUser, "registrationId", "userId");

    oAuthUser.setUserId("newUserId");

    assertEquals("newUserId", oAuthUser.getUserId());
  }

  @Test
  public void constructor_shouldInitializeAllFieldsCorrectly() {
    PentahoUser pentahoUser = new PentahoUser( tenant, "username", "password", "description", true);
    PentahoOAuthUser oAuthUser = new PentahoOAuthUser(pentahoUser, "registrationId", "userId");

    assertEquals( tenant, oAuthUser.getTenant());
    assertEquals("username", oAuthUser.getUsername());
    assertEquals("password", oAuthUser.getPassword());
    assertEquals("description", oAuthUser.getDescription());
    assertTrue(oAuthUser.isEnabled());
    assertEquals("registrationId", oAuthUser.getRegistrationId());
    assertEquals("userId", oAuthUser.getUserId());
  }
}