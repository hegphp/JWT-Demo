package com.example.jwtdemo.security.jwt;

import java.security.Key;
import com.example.jwtdemo.serviceImpl.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;


//This class has 3 function:
//Generate a JWT from username, date, expiration, secret
//Get username from JWT
//validate a JWT
@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    //Create a secret key to encode token JWT
    @Value("${swp391.app.jwtSecret}")
    private String jwtSecret;

    //Time exist of JWT Token, unit: ms
    @Value("${swp391.app.jwtExpirationMs}")
    private String jwtExpirationMs;

    //decode with secret key
    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        long moment = (new Date()).getTime() + Long.parseLong(jwtExpirationMs);

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date(moment)) //Time when JWT expired
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    //Get user name from Jwt Token
    public String getUserNameFromJwtToken(String token){
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJwt(token).getBody().getSubject();
    }

    //Validate JWT Token
    public boolean validateJwtToken(String authToken){
        try{
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        }catch(MalformedJwtException e){
            logger.error("Invalid JWT Token: {}", e.getMessage());
        }catch(ExpiredJwtException e){
            logger.error("JWT Token is Expired: {}",e.getMessage());
        }catch(UnsupportedJwtException e){
            logger.error("JWT Token is unsupported: {}", e.getMessage());
        }catch(IllegalArgumentException e){
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
