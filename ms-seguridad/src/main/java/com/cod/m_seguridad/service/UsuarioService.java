package com.cod.m_seguridad.service;

import com.cod.m_seguridad.entity.Usuario;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UsuarioService{
    UserDetailsService userDetailsService();
    Usuario crearUsuario(Usuario usuario);
    Usuario crearPersona(Usuario usuario);
    Usuario buscarPorEmail(String email);
    Usuario buscarUsuario(String usuario);
}
