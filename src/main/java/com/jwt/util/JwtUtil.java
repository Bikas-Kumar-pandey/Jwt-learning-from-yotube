package com.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {
    private String SECRET_KEY="secret";
//User Name
    public String extraUserName  (String token){
        return extraClaim(token, Claims::getSubject);
    }
//Expiration Date
    public Date extraExperiation(String token){
        return extraClaim(token,Claims::getExpiration);
    }

    public <T> T extraClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims=extractAllClaim(token);
        return claimsResolver.apply(claims);
    }
    private  Claims extractAllClaim(String token){
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }
    private Boolean isTokenExpired(String token){
        return extraExperiation(token).before(new Date());
    }
    //UserDetailService going to give user details here
    public String generateToken(UserDetails userDetails){
        Map<String, Object> claims=new HashMap<>();
        return createToken(claims,userDetails.getUsername());//it will create tokenmethod and pass claims which is empty now
    }
    //Subject is userr meassage has succesfully msgs
    private String createToken(Map<String, Object> claims,String subject){
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*10)) //10 hrs.
        .signWith(SignatureAlgorithm.HS256,SECRET_KEY).compact();//Signing with Digital
    }
    public Boolean validateToken(String token, UserDetails userDetails){
            final String username=extraUserName(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
