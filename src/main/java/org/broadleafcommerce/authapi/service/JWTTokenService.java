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

import io.jsonwebtoken.ExpiredJwtException;

import org.broadleafcommerce.authapi.domain.JWTUserDTO;


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
