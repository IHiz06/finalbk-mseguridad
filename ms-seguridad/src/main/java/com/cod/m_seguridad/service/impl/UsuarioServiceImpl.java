package com.cod.m_seguridad.service.impl;

import com.cod.m_seguridad.aggregates.Constants.Constants;
import com.cod.m_seguridad.entity.Rol;
import com.cod.m_seguridad.entity.Role;
import com.cod.m_seguridad.entity.Usuario;
import com.cod.m_seguridad.repository.RolRepository;
import com.cod.m_seguridad.repository.UsuarioRepository;
import com.cod.m_seguridad.service.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.NoSuchElementException;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UsuarioServiceImpl implements UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;

    @Override
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return usuarioRepository.findByEmail(username).orElseThrow(
                        ()-> new UsernameNotFoundException("USUARIO NO ENCONTRADO EN BASE DE DATOS"));
            }
        };
    }

    @Override
    public Usuario crearUsuario(Usuario usuario) {
        if (usuario.getPassword() == null || usuario.getPassword().isEmpty()) {
            throw new IllegalArgumentException("El password no puede ser nulo o vacío.");
        }
        if (usuario.getRoles() == null || usuario.getRoles().isEmpty()) {
            Set<Rol> roles = new HashSet<>();
            roles.add(getRoles(Role.USER));
            roles.add(getRoles(Role.ADMIN));
            usuario.setRoles(roles);
        }

        usuario.setPassword(new BCryptPasswordEncoder().encode(usuario.getPassword()));
        usuario.setIsAccountNonExpired(Constants.STATUS_ACTIVE);
        usuario.setIsAccountNonLocked(Constants.STATUS_ACTIVE);
        usuario.setIsCredentialsNonExpired(Constants.STATUS_ACTIVE);
        usuario.setIsEnabled(Constants.STATUS_ACTIVE);

        return usuarioRepository.save(usuario);
    }

    @Override
    public Usuario crearPersona(Usuario usuario) {
        if (usuario.getPassword() == null || usuario.getPassword().isEmpty()) {
            throw new IllegalArgumentException("El password no puede ser nulo o vacío.");
        }
        if (usuario.getRoles() == null || usuario.getRoles().isEmpty()) {
            Set<Rol> roles = new HashSet<>();
            roles.add(getRoles(Role.USER));
            usuario.setRoles(roles);
        }

        usuario.setPassword(new BCryptPasswordEncoder().encode(usuario.getPassword()));
        usuario.setIsAccountNonExpired(Constants.STATUS_ACTIVE);
        usuario.setIsAccountNonLocked(Constants.STATUS_ACTIVE);
        usuario.setIsCredentialsNonExpired(Constants.STATUS_ACTIVE);
        usuario.setIsEnabled(Constants.STATUS_ACTIVE);

        return usuarioRepository.save(usuario);
    }


    @Override
    public Usuario buscarPorEmail(String email) {
        return usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new NoSuchElementException("Usuario no encontrado con el email: " + email));
    }

    @Override
    public Usuario buscarUsuario(String usuario) {
        return usuarioRepository.findByUsuario(usuario)
                .orElseThrow(()-> new NoSuchElementException("Usuario no econtrado con el usuario: "+usuario));
    }

    private Rol getRoles(Role rolBuscado){
        return rolRepository.findByNombreRol(rolBuscado.name())
                .orElseThrow(
                        () -> new RuntimeException(
                                "ERROR EL ROL NO EXISTE :" + rolBuscado.name()));
    }


}
