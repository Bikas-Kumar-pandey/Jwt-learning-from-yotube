package com.jwt.controller;

import com.jwt.jwtService.MyUserDetailService;
import com.jwt.model.AuthenticateRequest;
import com.jwt.model.AuthenticateResponse;
import com.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class JwtController {
    @Autowired
    private AuthenticationManager authenticationManager;//need to authenticate requested passowrd and username

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private MyUserDetailService myUserDetailService;

    @GetMapping("/hello")
    public String hello() {
        return "hello world";
    }

    //When i call this method first should not authenticate so configuration is don in Security ConfiurationClass
    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticateRequest authenticateRequest) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticateRequest.getUsername(), authenticateRequest.getPassword()));
        } catch (Exception e) {
            throw new Exception("Incorrect username or password", e);
        }
        //Need to get username and password saved here i have save in MyUserDetailServiceClass
        final UserDetails userDetails = myUserDetailService.loadUserByUsername(authenticateRequest.getUsername());
        //Need to create jwt token
        final String jwt = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticateResponse(jwt));
        //eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiaWthcyIsImV4cCI6MTY2NTM4Mzk1MCwiaWF0IjoxNjY1MzgzMzUwfQ.0RTEJbb_r3kb_7DiA8AoNUw2O06ZNcsVJhcVuaqZQBo
        //aboveis response where client holds in local torage or in cookies anywhere else and passes to api subsequent request
    }
}
