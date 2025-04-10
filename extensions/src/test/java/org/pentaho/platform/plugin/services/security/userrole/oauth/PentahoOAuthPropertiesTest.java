package org.pentaho.platform.plugin.services.security.userrole.oauth;

import org.apache.log4j.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.pentaho.platform.api.engine.IConfiguration;
import org.pentaho.platform.api.engine.ISystemConfig;
import org.pentaho.platform.util.oauth.PentahoOAuthProperties;

import java.io.IOException;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class PentahoOAuthPropertiesTest {

  @Mock
  private ISystemConfig systemConfig;

  @Mock
  private Logger logger;

  @Test
  public void getValue_shouldReturnPropertyValueWhenKeyExists() throws IOException, NoSuchFieldException, IllegalAccessException {
    String key = "testKey";
    String value = "testValue";

    IConfiguration config = mock(IConfiguration.class);
    Properties properties = new Properties();
    properties.setProperty(key, value);

    when(systemConfig.getConfiguration("oauth")).thenReturn(config);
    when(config.getProperties()).thenReturn(properties);

    PentahoOAuthProperties pentahoOAuthProperties = new PentahoOAuthProperties();
    var systemConfigField = PentahoOAuthProperties.class.getDeclaredField("systemConfig");
    systemConfigField.setAccessible(true);
    systemConfigField.set(pentahoOAuthProperties, systemConfig);

    String result = pentahoOAuthProperties.getValue(key);

    assertEquals(value, result);
  }

  @Test
  public void getValue_shouldReturnNullWhenKeyDoesNotExist() throws IOException, NoSuchFieldException, IllegalAccessException {
    String key = "nonExistentKey";

    IConfiguration config = mock(IConfiguration.class);
    Properties properties = new Properties();

    when(systemConfig.getConfiguration("oauth")).thenReturn(config);
    when(config.getProperties()).thenReturn(properties);

    PentahoOAuthProperties pentahoOAuthProperties = new PentahoOAuthProperties();
    var systemConfigField = PentahoOAuthProperties.class.getDeclaredField("systemConfig");
    systemConfigField.setAccessible(true);
    systemConfigField.set(pentahoOAuthProperties, systemConfig);

    String result = pentahoOAuthProperties.getValue(key);

    assertNull(result);
  }

  @Test
  public void getValue_shouldReturnNullWhenPropertiesAreNotLoaded() throws IOException, NoSuchFieldException, IllegalAccessException {
    IConfiguration config = mock(IConfiguration.class);

    when(systemConfig.getConfiguration("oauth")).thenReturn(config);
    when(config.getProperties()).thenThrow(new IOException());

    PentahoOAuthProperties pentahoOAuthProperties = new PentahoOAuthProperties();
    var systemConfigField = PentahoOAuthProperties.class.getDeclaredField("systemConfig");
    systemConfigField.setAccessible(true);
    systemConfigField.set(pentahoOAuthProperties, systemConfig);

    String result = pentahoOAuthProperties.getValue("anyKey");

    assertNull(result);
  }

}