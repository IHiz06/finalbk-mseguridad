package com.cod.m_seguridad.aggregates.request;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignUpRequest {
    private String nombres;
    private String apellidos;
    private String usuario;
    private String email;
    private String password;
}
