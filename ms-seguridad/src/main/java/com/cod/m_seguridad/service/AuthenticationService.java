package com.cod.m_seguridad.service;

import com.cod.m_seguridad.aggregates.request.SignInRequest;
import com.cod.m_seguridad.aggregates.request.SignUpRequest;
import com.cod.m_seguridad.aggregates.response.SignInResponse;
import com.cod.m_seguridad.entity.Usuario;

public interface AuthenticationService {

    Usuario signUpUser(SignUpRequest signUpRequest);
    Usuario signUpAdmin(SignUpRequest signUpRequest);

    SignInResponse signIn(SignInRequest signInRequest);
}
