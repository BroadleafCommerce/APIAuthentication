/*-
 * #%L
 * BroadleafCommerce API Authentication
 * %%
 * Copyright (C) 2009 - 2017 Broadleaf Commerce
 * %%
 * Licensed under the Broadleaf Fair Use License Agreement, Version 1.0
 * (the "Fair Use License" located  at http://license.broadleafcommerce.org/fair_use_license-1.0.txt)
 * unless the restrictions on use therein are violated and require payment to Broadleaf in which case
 * the Broadleaf End User License Agreement (EULA), Version 1.1
 * (the "Commercial License" located at http://license.broadleafcommerce.org/commercial_license-1.1.txt)
 * shall apply.
 * 
 * Alternatively, the Commercial License may be replaced with a mutually agreed upon license (the "Custom License")
 * between you and Broadleaf Commerce. You may not use this file except in compliance with the applicable license.
 * #L%
 */
package org.broadleafcommerce.authapi.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.broadleafcommerce.authapi.filter.AccessTokenAuthenticationFilter;
import org.broadleafcommerce.authapi.filter.ApiLoginFilter;
import org.broadleafcommerce.authapi.filter.RefreshTokenAuthenticationFilter;
import org.broadleafcommerce.authapi.filter.ApiRegisterFilter;

/**
 * @author Nick Crum ncrum
 */
public interface ApiAuthenticationRequestFactory {
    AccessTokenAuthenticationFilter buildAccessTokenAuthenticationFilter(String url, AuthenticationManager authenticationManager) throws Exception;

    RefreshTokenAuthenticationFilter buildRefreshTokenAuthenticationFilter(String url, AuthenticationManager authenticationManager) throws Exception;

    ApiLoginFilter buildLoginFilter(String url, AuthenticationManager authenticationManager) throws Exception;

    ApiRegisterFilter buildRegisterFilter(String url, AuthenticationManager authenticationManager) throws Exception;
}
