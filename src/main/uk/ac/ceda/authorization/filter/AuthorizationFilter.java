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

package uk.ac.ceda.authorization.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Action;

import esg.orp.app.SAMLAuthorizer;
//import uk.ac.ceda.authorization.Authorizer;
import uk.ac.ceda.common.AccessControlFilter;

/*
 * Filter for authorizing requests.
 * 
 * @author William Tucker
 */
public class AuthorizationFilter extends AccessControlFilter
{
    private SAMLAuthorizer authorizer;
    
    private final Log LOG = LogFactory.getLog(this.getClass());
    
    /**
     * @see Filter#destroy()
     */
    public void destroy() { }
    
    /**
     * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        String openID = getAuthenticatedUser(request);
        if (LOG.isDebugEnabled() && openID != null)
            LOG.debug("Found authentication attribute, openid = " + openID);
        String url = httpRequest.getRequestURL().toString();
        
        if (LOG.isDebugEnabled())
            LOG.debug("Requesting authorization for URL = " + url);
        final boolean authorized = authorizer.authorize(openID, url, Action.READ_ACTION);
        if (LOG.isDebugEnabled())
            LOG.debug("Openid = " + openID + " url = " + url + " operation = " + Action.READ_ACTION + " authorization result = " + authorized);
        
        if (authorized)
        {
            // Mark request as authorized
            authorizeRequest(request);
        }
        
        // pass the request along the filter chain
        chain.doFilter(request, response);
    }

    /**
     * @see Filter#init(FilterConfig)
     */
    public void init(FilterConfig filterConfig) throws ServletException
    {
        this.authorizer = new SAMLAuthorizer();
        
        if (filterConfig != null)
        {
            String[] endpoints = filterConfig.getInitParameter("authorizationServiceUrl").split(",");
            this.authorizer.setEndpoints(endpoints);
        }
    }
}
