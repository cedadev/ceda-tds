/*
 * Copyright 2018 United Kingdom Research and Innovation
 * 
 * Licensed under the following BSD license:
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

package uk.ac.ceda.common;

import javax.servlet.Filter;
import javax.servlet.ServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/*
 * Abstract class containing methods for getting and setting access control
 * request attributes.
 * 
 * @author William Tucker
 */
public abstract class AccessControlFilter implements Filter
{
    final static String AUTHENTICATION_REQUEST_ATTRIBUTE = "uk.ac.ceda.authn";
    final static String AUTHORIZATION_REQUEST_ATTRIBUTE = "uk.ac.ceda.authz";

    private final Log LOG = LogFactory.getLog(this.getClass());

    /**
     * Method to set the authenticated user for a request.
     * @param request
     * @param userID
     */
    protected void authenticateUser(final ServletRequest request, String userID)
    {
        request.setAttribute(AUTHENTICATION_REQUEST_ATTRIBUTE, userID);
        if (LOG.isDebugEnabled())
            LOG.debug(String.format("Setting '%s' attribute", AUTHENTICATION_REQUEST_ATTRIBUTE));
    }

    /**
     * Method to get the authenticated user for a request.
     * @param request
     */
    protected String getAuthenticatedUser(final ServletRequest request)
    {
        return (String)request.getAttribute(AUTHENTICATION_REQUEST_ATTRIBUTE);
    }

    /**
     * Method to set the authorization attribute of a request to true.
     * @param request
     */
    protected void authorizeRequest(final ServletRequest request)
    {
        request.setAttribute(AUTHORIZATION_REQUEST_ATTRIBUTE, true);
        if (LOG.isDebugEnabled())
            LOG.debug(String.format("Setting '%s' attribute", AUTHORIZATION_REQUEST_ATTRIBUTE));
    }

    /**
     * Returns true if the request has been authorized.
     * @param request
     */
    protected boolean isAuthorized(final ServletRequest request)
    {
        boolean authorized = false;
        
        Object attribute = request.getAttribute(AUTHORIZATION_REQUEST_ATTRIBUTE);
        if (attribute instanceof Boolean)
            authorized = (boolean)attribute;
        
        return authorized;
    }

}
