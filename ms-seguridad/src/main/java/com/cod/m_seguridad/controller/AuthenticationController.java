package com.cod.m_seguridad.controller;


import com.cod.m_seguridad.aggregates.request.SignInRequest;
import com.cod.m_seguridad.aggregates.response.SignInResponse;
import com.cod.m_seguridad.entity.Usuario;
import com.cod.m_seguridad.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/v1")
@RequiredArgsConstructor

public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/signupuser")
    public ResponseEntity<Usuario> signUpUser(
            @RequestBody com.cod.m_seguridad.aggregates.request.SignUpRequest signUpRequest) {
        return ResponseEntity.ok(authenticationService
                .signUpUser(signUpRequest));
    }

    @PostMapping("/signupadmin")
    public ResponseEntity<Usuario> signUpAdmin(
            @RequestBody com.cod.m_seguridad.aggregates.request.SignUpRequest signUpRequest) {
        return ResponseEntity.ok(authenticationService
                .signUpAdmin(signUpRequest));
    }

    @PostMapping("/signin")
    public ResponseEntity<SignInResponse> signIn(
            @RequestBody SignInRequest signInRequest) {
        return ResponseEntity.ok(authenticationService
                .signIn(signInRequest));

    }

}