package com.ss.sbank.user.security;

import com.ss.sbank.user.entity.UserRole;
import com.ss.sbank.user.service.AuthService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;

@Component
public class JwtTokenProvider implements Serializable {

    private static final long serialVersionUID = 3618665182399728556L;

    @Autowired
    private AuthService authService;

    // Get value from application.properties
    @Value("${jwtSecret}")
    private String jwtSecret;

    // Calculating a week in milliseconds for validity
    private final Integer validityInMilliseconds = 7 * 24 * 60 * 60 * 1000;

    public String generateToken(Integer userId, String username, UserRole role) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("auth", role);
        claims.put("id", userId);

        Date now = new Date();
        Date expiration = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt((Date) now)
                .setExpiration(expiration)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public Authentication getAuthentication(String username) {
        UserDetails userDetails = authService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(),
                userDetails.getPassword(),
                userDetails.getAuthorities()
        );
    }

    public Claims getClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
    }
}
