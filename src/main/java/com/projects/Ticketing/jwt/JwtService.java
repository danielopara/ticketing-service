package com.projects.Ticketing.jwt;

import com.projects.Ticketing.model.Roles;
import com.projects.Ticketing.model.User;
import com.projects.Ticketing.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@Service
public class JwtService {
//    private static final String SECRET_KEY = System.getenv("SECRET_KEY");
    @Value("${SECRET_KEY}")
    private String secretKey;
    private final UserRepository userRepository;

    public JwtService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    private Key getSigningKey(){

        if (secretKey == null || secretKey.isEmpty()) {
            throw new RuntimeException("Secret key is not set");
        }
        byte[] keyByte = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyByte);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            throw new RuntimeException("Invalid token: " + e.getMessage(), e);
        }
    }

    private <T>T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(Map<String, Object> getDetails, Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        Optional<User> userOptional = userRepository.findByEmail(userDetails.getUsername());

        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }

        Roles role = userOptional.get().getRole();
        getDetails.put("role", role.toString());

        return Jwts.builder()
                .setClaims(getDetails)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    private Date extractExpiration(String token){return extractClaim(token, Claims::getExpiration);}

    private boolean isTokenExpired(String token){return extractExpiration(token).before(new Date());}

    private String extractRole(String token){
        Claims claims = extractAllClaims(token);
        Object role = claims.get("role");
        return role.toString();
    }

    public Date extractTokenCreation(String token){
        return extractClaim(token, Claims::getIssuedAt);
    }

//    public String generateToken(Authentication authentication){
//        return generateToken(new HashMap<>(), authentication);
//    }

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
}
