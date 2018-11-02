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

import org.broadleafcommerce.authapi.filter.AccessTokenAuthenticationFilter;
import org.broadleafcommerce.authapi.filter.ApiLoginFilter;
import org.broadleafcommerce.authapi.filter.ApiRegisterFilter;
import org.broadleafcommerce.authapi.filter.RefreshTokenAuthenticationFilter;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

/**
 * @author Nick Crum ncrum
 */
@Service("blApiAuthenticationRequestFactory")
public class ApiAuthenticationRequestFactoryImpl implements ApiAuthenticationRequestFactory {

    protected final Environment environment;
    protected final AuthenticationTokenService authenticationTokenService;
    protected final AuthenticationSuccessHandler authenticationSuccessHandler;
    protected final CustomerStateService customerStateService;

    public ApiAuthenticationRequestFactoryImpl(Environment environment, AuthenticationTokenService authenticationTokenService,
                                               AuthenticationSuccessHandler authenticationSuccessHandler,
                                               CustomerStateService customerStateService) {
        this.environment = environment;
        this.authenticationTokenService = authenticationTokenService;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.customerStateService = customerStateService;
    }

    @Override
    public AccessTokenAuthenticationFilter buildAccessTokenAuthenticationFilter(String url, AuthenticationManager authenticationManager) throws Exception {
        return new AccessTokenAuthenticationFilter(url, authenticationManager);
    }

    @Override
    public RefreshTokenAuthenticationFilter buildRefreshTokenAuthenticationFilter(String url, AuthenticationManager authenticationManager) throws Exception {
        return new RefreshTokenAuthenticationFilter(url, authenticationManager, environment, authenticationTokenService);
    }

    @Override
    public ApiLoginFilter buildLoginFilter(String url, AuthenticationManager authenticationManager) throws Exception {
        return new ApiLoginFilter(url, authenticationManager, authenticationSuccessHandler);
    }

    @Override
    public ApiRegisterFilter buildRegisterFilter(String url, AuthenticationManager authenticationManager) throws Exception {
        return new ApiRegisterFilter(url, authenticationManager, authenticationSuccessHandler, customerStateService);
    }
}
