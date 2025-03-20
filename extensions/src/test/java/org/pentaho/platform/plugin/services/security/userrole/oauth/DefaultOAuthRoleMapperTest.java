package org.pentaho.platform.plugin.services.security.userrole.oauth;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import org.pentaho.platform.engine.security.DefaultOAuthRoleMapper;

import static org.junit.Assert.assertEquals;

import java.util.Map;

@RunWith(MockitoJUnitRunner.class)
public class DefaultOAuthRoleMapperTest {

  @Test
  public void toPentahoRole_shouldReturnMappedRoleWhenMappingExists() {
    Map<String, String> roleMap = Map.of("thirdPartyRole1", "pentahoRole1");
    DefaultOAuthRoleMapper roleMapper = new DefaultOAuthRoleMapper(roleMap);

    String result = roleMapper.toPentahoRole("thirdPartyRole1");

    assertEquals("pentahoRole1", result);
  }

  @Test
  public void toPentahoRole_shouldReturnSameRoleWhenMappingDoesNotExist() {
    Map<String, String> roleMap = Map.of("thirdPartyRole1", "pentahoRole1");
    DefaultOAuthRoleMapper roleMapper = new DefaultOAuthRoleMapper(roleMap);

    String result = roleMapper.toPentahoRole("thirdPartyRole2");

    assertEquals("thirdPartyRole2", result);
  }

  @Test
  public void fromPentahoRole_shouldReturnMappedThirdPartyRoleWhenMappingExists() {
    Map<String, String> roleMap = Map.of("thirdPartyRole1", "pentahoRole1");
    DefaultOAuthRoleMapper roleMapper = new DefaultOAuthRoleMapper(roleMap);

    String result = roleMapper.fromPentahoRole("pentahoRole1");

    assertEquals("thirdPartyRole1", result);
  }

  @Test
  public void fromPentahoRole_shouldReturnSameRoleWhenMappingDoesNotExist() {
    Map<String, String> roleMap = Map.of("thirdPartyRole1", "pentahoRole1");
    DefaultOAuthRoleMapper roleMapper = new DefaultOAuthRoleMapper(roleMap);

    String result = roleMapper.fromPentahoRole("pentahoRole2");

    assertEquals("pentahoRole2", result);
  }

  @Test
  public void fromPentahoRole_shouldReturnSameRoleWhenRoleMapIsEmpty() {
    Map<String, String> roleMap = Map.of();
    DefaultOAuthRoleMapper roleMapper = new DefaultOAuthRoleMapper(roleMap);

    String result = roleMapper.fromPentahoRole("pentahoRole1");

    assertEquals("pentahoRole1", result);
  }

  @Test
  public void toPentahoRole_shouldReturnSameRoleWhenRoleMapIsEmpty() {
    Map<String, String> roleMap = Map.of();
    DefaultOAuthRoleMapper roleMapper = new DefaultOAuthRoleMapper(roleMap);

    String result = roleMapper.toPentahoRole("thirdPartyRole1");

    assertEquals("thirdPartyRole1", result);
  }
}
