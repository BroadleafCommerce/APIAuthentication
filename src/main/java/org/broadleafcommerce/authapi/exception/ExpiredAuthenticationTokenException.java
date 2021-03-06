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
package org.broadleafcommerce.authapi.exception;

import org.broadleafcommerce.authapi.provider.AccessTokenAuthenticationProvider;
import org.broadleafcommerce.authapi.provider.RefreshTokenAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;

/**
 * This exception is thrown by the {@code AccessTokenService} when an expired token is found. This exception's
 * message is then returned within a 401 response to indicate the request was unauthorized due to an expired token.
 *
 * @see AccessTokenAuthenticationProvider
 * @see RefreshTokenAuthenticationProvider
 * @author Nick Crum ncrum
 */
public class ExpiredAuthenticationTokenException extends AuthenticationException {

    public ExpiredAuthenticationTokenException(Throwable t) {
        super("EXPIRED_ACCESS_TOKEN", t);
    }
}
