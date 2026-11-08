package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.repository.MascotaRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component("securityRules")
@RequiredArgsConstructor
public class SecurityRules {

    private final MascotaRepository mascotaRepository;

    public boolean isMascotaOwner(Long mascotaId, Authentication authentication) {
        // 1. Obtenemos el usuario logueado
        UsuarioDetails usuarioLogueado = (UsuarioDetails) authentication.getPrincipal();

        // 2. Validamos si la mascota pertenece a ese usuario
        return mascotaRepository.existsByIdAndPropietarioId(mascotaId, usuarioLogueado.getUsuario().getId());
    }
}