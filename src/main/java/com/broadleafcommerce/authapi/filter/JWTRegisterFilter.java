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
package com.broadleafcommerce.authapi.filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import com.broadleafcommerce.authapi.domain.RegisterDTO;
import com.broadleafcommerce.authapi.filter.handler.JWTAuthenticationSuccessHandler;
import com.broadleafcommerce.authapi.service.CustomerStateService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Collections;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This filter is responseponsible for handling the login for registered customers. This is not automatically registered with
 * the filter chain and requestuiresponse the filter to be added before the {@link JWTAuthenticationTokenFilter}.
 *
 * @author Nick Crum ncrum
 */
public class JWTRegisterFilter extends AbstractAuthenticationProcessingFilter {

    protected final JWTAuthenticationSuccessHandler successHandler;
    protected final CustomerStateService customerStateService;

    public JWTRegisterFilter(String url, AuthenticationManager authenticationManager, JWTAuthenticationSuccessHandler successHandler, CustomerStateService customerStateService) {
        super(url);
        this.successHandler = successHandler;
        this.customerStateService = customerStateService;
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        RegisterDTO dto = new ObjectMapper()
                .readValue(request.getInputStream(), RegisterDTO.class);

        customerStateService.registerNewCustomer(dto);

        return getAuthenticationManager().authenticate(
                new UsernamePasswordAuthenticationToken(
                        dto.getEmailAddress(),
                        dto.getPassword(),
                        Collections.<GrantedAuthority>emptyList()
                )
        );
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response, FilterChain chain,
            Authentication authentication) throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }
}