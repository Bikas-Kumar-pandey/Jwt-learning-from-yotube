package com.jwt.filters;

import com.jwt.jwtService.MyUserDetailService;
import com.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilters  extends OncePerRequestFilter


{//Examine request in header

    @Autowired
    private MyUserDetailService myUserDetailService;
    @Autowired
    private JwtUtil jwtUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
final String autherizationHeader=request.getHeader("Authorization");
String username=null;
String jwt=null;

if(autherizationHeader!=null && autherizationHeader.startsWith("Bearer ")){
    jwt=autherizationHeader.substring(7); //Bearer : pass Bearer  and set in jwt
    username=jwtUtil.extraUserName(jwt);
}
if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null){
    UserDetails userDetails = this.myUserDetailService.loadUserByUsername(username);
    if(jwtUtil.validateToken(jwt,userDetails)){
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =new UsernamePasswordAuthenticationToken(userDetails,
                null, userDetails.getAuthorities());
//it validate user details is valid or not expired
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }
}
        filterChain.doFilter(request,response);
    }
}
