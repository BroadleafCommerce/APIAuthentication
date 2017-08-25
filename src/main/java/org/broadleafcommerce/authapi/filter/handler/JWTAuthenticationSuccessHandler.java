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
package org.broadleafcommerce.authapi.filter.handler;

import org.broadleafcommerce.profile.core.service.CustomerUserDetails;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.broadleafcommerce.authapi.service.JWTTokenService;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Nick Crum ncrum
 */
@Component("blJWTAuthenticationSuccessHandler")
@ConditionalOnProperty("blc.auth.jwt.enabled")
public class JWTAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    protected final Environment environment;
    protected final JWTTokenService jwtTokenService;

    public JWTAuthenticationSuccessHandler(Environment environment, JWTTokenService jwtTokenService) {
        this.environment = environment;
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        CustomerUserDetails customerUserDetails = (CustomerUserDetails) authentication.getPrincipal();
        String authToken = jwtTokenService.generateAuthenticationToken(customerUserDetails.getId(), customerUserDetails.getUsername(), false, null);
        String refreshToken = jwtTokenService.generateRefreshToken(customerUserDetails.getId(), customerUserDetails.getUsername(), false, null);

        response.addHeader("Authorization", "Bearer " + authToken);
        response.addCookie(buildRefreshTokenCookie(refreshToken));
    }

    protected Cookie buildRefreshTokenCookie(String refreshToken) {
        Cookie cookie = new Cookie(getRefreshTokenCookieName(), refreshToken);
        cookie.setPath("/");
        cookie.setMaxAge(getRefreshTokenCookieMaxAge());
        cookie.setHttpOnly(true);
        return cookie;
    }

    protected String getRefreshTokenCookieName() {
        return environment.getProperty("blc.auth.jwt.refresh.cookie.name");
    }

    protected int getRefreshTokenCookieMaxAge() {
        return environment.getProperty("blc.auth.jwt.refresh.cookie.expiration", Integer.class);
    }
}
