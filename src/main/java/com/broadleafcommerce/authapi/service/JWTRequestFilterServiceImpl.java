/*-
 * #%L
 * BroadleafCommerce API Authentication
 * %%
 * Copyright (C) 2009 - 2017 Broadleaf Commerce
 * %%
 * Licensed under the Broadleaf End User License Agreement (EULA), Version 1.1
 * (the "Commercial License" located at http://license.broadleafcommerce.org/commercial_license-1.1.txt).
 * 
 * Alternatively, the Commercial License may be replaced with a mutually agreed upon license (the "Custom License")
 * between you and Broadleaf Commerce. You may not use this file except in compliance with the applicable license.
 * 
 * NOTICE:  All information contained herein is, and remains
 * the property of Broadleaf Commerce, LLC
 * The intellectual and technical concepts contained
 * herein are proprietary to Broadleaf Commerce, LLC
 * and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Broadleaf Commerce, LLC.
 * #L%
 */
package com.broadleafcommerce.authapi.service;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Service;
import com.broadleafcommerce.authapi.filter.JWTAuthenticationTokenFilter;
import com.broadleafcommerce.authapi.filter.JWTLoginFilter;
import com.broadleafcommerce.authapi.filter.JWTRefreshTokenFilter;
import com.broadleafcommerce.authapi.filter.JWTRegisterFilter;
import com.broadleafcommerce.authapi.filter.handler.JWTAuthenticationSuccessHandler;

/**
 * @author Nick Crum ncrum
 */
@Service("blJWTRequestFilterService")
@ConditionalOnProperty(name = "blc.auth.jwt.enabled")
public class JWTRequestFilterServiceImpl implements JWTRequestFilterService {

    protected final Environment environment;
    protected final JWTTokenService jwtTokenService;
    protected final JWTAuthenticationSuccessHandler authenticationSuccessHandler;
    protected final CustomerStateService customerStateService;

    public JWTRequestFilterServiceImpl(Environment environment, JWTTokenService jwtTokenService,
                                       JWTAuthenticationSuccessHandler authenticationSuccessHandler,
                                       CustomerStateService customerStateService) {
        this.environment = environment;
        this.jwtTokenService = jwtTokenService;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.customerStateService = customerStateService;
    }

    @Override
    public JWTAuthenticationTokenFilter buildJWTAuthenticationTokenFilter(AuthenticationManager authenticationManager) throws Exception {
        return new JWTAuthenticationTokenFilter(authenticationManager);
    }

    @Override
    public JWTRefreshTokenFilter buildJWTRefreshTokenFilter(String url, AuthenticationManager authenticationManager) throws Exception {
        return new JWTRefreshTokenFilter(url, authenticationManager, environment, jwtTokenService);
    }

    @Override
    public JWTLoginFilter buildJWTLoginFilter(String url, AuthenticationManager authenticationManager) throws Exception {
        return new JWTLoginFilter(url, authenticationManager, authenticationSuccessHandler);
    }

    @Override
    public JWTRegisterFilter buildJWTRegisterFilter(String url, AuthenticationManager authenticationManager) throws Exception {
        return new JWTRegisterFilter(url, authenticationManager, authenticationSuccessHandler, customerStateService);
    }
}