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

    @Value("${SECRET_KEY}")
    private String secretKey;

    @Value("${REFRESH_TOKEN_EXPIRATION_MS}")
    private long refreshTokenMs;

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

//    private String generateToken(Map<String, Object> getDetails, Authentication authentication) {
//        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//        Optional<User> userOptional = userRepository.findByEmail(userDetails.getUsername());
//
//        if (userOptional.isEmpty()) {
//            throw new RuntimeException("User not found");
//        }
//
//        String role = userOptional.get().getRole();
//        getDetails.put("role", role);
//
//        return Jwts.builder()
//                .setClaims(getDetails)
//                .setSubject(userDetails.getUsername())
//                .setIssuedAt(new Date())
//                .setExpiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000))
//                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
//                .compact();
//    }

    private String generateToken(Map<String, Object> getDetails, String username, long expirationMs) {
        return Jwts.builder()
                .setClaims(getDetails)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
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

    public void extractTokenCreation(String token){
        extractClaim(token, Claims::getIssuedAt);
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

    public String generateAccessToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        Optional<User> userOptional = userRepository.findByEmail(userDetails.getUsername());

        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }

        String role = userOptional.get().getRole();
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role);

        // Generate access token (valid for 1 day)
        return generateToken(claims, userDetails.getUsername(), 24 * 60 * 60 * 1000);
    }

    public String generateAccessTokenWithRefreshToken(String refreshToken){
        String username = extractUsername(refreshToken);

        Optional<User> userOptional = userRepository.findByEmail(username);

        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }

        String role = userOptional.get().getRole();
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role);


        return generateToken(claims, username, 24 * 60 * 60 * 1000);
    }

    public String generateRefreshToken(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        Map<String, Object> claims = new HashMap<>();

        // Generate refresh token with longer expiration time
        return generateToken(claims, userDetails.getUsername(), refreshTokenMs);
    }
}
