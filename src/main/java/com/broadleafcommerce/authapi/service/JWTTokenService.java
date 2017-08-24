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

import io.jsonwebtoken.ExpiredJwtException;

import com.broadleafcommerce.authapi.domain.JWTUserDTO;


/**
 * @author Nick Crum ncrum
 */
public interface JWTTokenService {
    JWTUserDTO parseAuthenticationToken(String token) throws ExpiredJwtException;

    JWTUserDTO parseRefreshToken(String token) throws ExpiredJwtException;

    String generateAuthenticationToken(Long userId, String username, boolean isCrossAppAuth, String commaSeparatedAuthorities);

    String generateRefreshToken(Long userId, String username, boolean isCrossAppAuth, String commaSeparatedAuthorities);

    Long parseCustomerToken(String customerToken);

    String generateCustomerToken(Long customerId);
}
