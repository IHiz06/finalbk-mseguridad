package com.cod.m_seguridad.controller;

import com.cod.m_seguridad.entity.Usuario;
import com.cod.m_seguridad.service.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/usuario")
@RequiredArgsConstructor
public class UsuarioController {
    private final UsuarioService usuarioService;

    @PostMapping("/crearAdmin")
    public ResponseEntity<Usuario> crearUsuario(@RequestBody Usuario usuario){
        return new ResponseEntity<>(usuarioService.crearUsuario(usuario), HttpStatus.CREATED);
    }

    @PostMapping("/crearPersona")
    public ResponseEntity<Usuario> crearPersona(@RequestBody Usuario usuario){
        return new ResponseEntity<>(usuarioService.crearPersona(usuario), HttpStatus.CREATED);
    }

    @GetMapping("/buscarEmail/{email}")
    public ResponseEntity<Usuario> buscarPorEmail(@PathVariable String email){
        return new ResponseEntity<>(usuarioService.buscarPorEmail(email), HttpStatus.OK);
    }

    @GetMapping("/buscarUsuario/{usuario}")
    public ResponseEntity<Usuario> buscarPorUsuario(@PathVariable String usuario){
        return new ResponseEntity<>(usuarioService.buscarUsuario(usuario), HttpStatus.OK);
    }
}
