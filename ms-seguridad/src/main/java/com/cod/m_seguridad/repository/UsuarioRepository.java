package com.cod.m_seguridad.repository;

import com.cod.m_seguridad.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByUsuario(String usuario);
    Optional<Usuario> findByEmail(String email);
}
