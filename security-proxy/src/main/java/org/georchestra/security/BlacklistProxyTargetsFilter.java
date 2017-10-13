package org.georchestra.security;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.GenericFilterBean;

public class BlacklistProxyTargetsFilter extends GenericFilterBean {

    private List<InetAddress> blacklistedHosts;

    public BlacklistProxyTargetsFilter(String blacklistedHosts) {
        this.blacklistedHosts = new ArrayList<InetAddress>();
        try {
            for (String h :  blacklistedHosts.split(",")) {
                // TODO: what if DNS update ?
              this.blacklistedHosts.add(InetAddress.getByName(h));
            }
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (! (request instanceof HttpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }

        if (! (response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        String proxyUrl = request.getParameter("url");

        if (proxyUrl == null) {
            chain.doFilter(request, response);
            return;
        }

        String requestedEndPoint = req.getRequestURI();
        // Note: this filter is chained in the Spring filter chain, which
        // comes before the urlrewrite one (see in the web.xml). Hence
        // instead of /sec/proxy, we are looking for /proxy.
        if (! requestedEndPoint.startsWith("/proxy")) {
            chain.doFilter(request, response);
            return;
        }
        URI reqRemoteHost;
        try {
            reqRemoteHost = new URI(proxyUrl);
        } catch (URISyntaxException e) {
            chain.doFilter(request, response);
            return;
        }

        if (this.blacklistedHosts.contains(InetAddress.getByName(reqRemoteHost.getHost()))) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        chain.doFilter(request, response);
        return;
    }


    @Override
    public void destroy() {
    }

}
