package com.ss.sbank.user.security;

import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@AllArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private static Logger log = LoggerFactory.getLogger(JwtTokenFilter.class);

    private JwtTokenProvider tokenProvider;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("JwtTokenFilter : doFilterInternal");
        // Get the value from the Key "Authorization"
        String token = request.getHeader("Authorization");

        // Check if token exists
        if (token != null) {
            try {
                Claims claims = tokenProvider.getClaimsFromToken(token);

                // Check if token is expired
                if (!claims.getExpiration().before(new Date())) {
                    Authentication authentication = tokenProvider.getAuthentication(claims.getSubject());
                    if (authentication.isAuthenticated()) {
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
            catch (RuntimeException e) {
                // Send 401 error if token is not valid
                try {
                    SecurityContextHolder.clearContext();
                    response.setContentType("application/json");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().println(
                            "Expired or invalid JWT token" + e.getMessage()
                    );
                }
                catch (IOException err) {
                    err.printStackTrace();
                }
                return;
            }
        }
        else {
            log.info("creating token using AuthService.authenticate method");
        }

        // Continue the rest of the filters
        filterChain.doFilter(request, response);
    }
}
