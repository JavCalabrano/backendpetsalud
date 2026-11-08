package com.petsalud.backendpetsalud.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // secreto que vamos a esconder
    private static final String SECRET_KEY="d31b42becd07eb8cdd403e0ba24f9dec5dce216761b826fd861025fb5bfea017";  // Secreto despues pasarlo a oculta

    // puerta a la información del token
    public String getToken(UsuarioDetails user) {
        return generarToken(new HashMap<>(), user);
    }

    // generador del token
    private String generarToken(Map<String,Object> extraClaims, UsuarioDetails user) {
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + (1000 * 60 * 30)))
                .signWith(obtenerKey())
                .compact();
    }

    // crea la key para la firma
    private Key obtenerKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // valida si el token es valido por
    public boolean isTokenValid(String token, UsuarioDetails usuarioDetails) {
        final String username = obtenerUsernameFromToken(token);
        return (username.equals(usuarioDetails.getUsername()) && !isTokenExpired(token));
    }

    // obtiene todas claims para usar en las validaciones
    private Claims getAllClaims(String token) {
        return Jwts.parser()
                .verifyWith((javax.crypto.SecretKey) obtenerKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // obtiene el claim del username o email de la cuenta
    public String obtenerUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }

    // obtiene el claim que se le indique por metodo, la T indica tipo desconocido hasta que obtiene el resultado
    private <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // obtiene el tiempo de expiracion
    private Date getExpiration(String token) {
        return getClaim(token, Claims::getExpiration);
    }

    // verifica si el paso o no el tiempo de expiracion
    private boolean isTokenExpired(String token) {
        return getExpiration(token).before(new Date());
    }

}
