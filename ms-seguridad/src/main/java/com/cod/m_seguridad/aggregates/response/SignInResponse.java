package com.cod.m_seguridad.aggregates.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class SignInResponse {
    private String token;
    private String refreshToken;
}
