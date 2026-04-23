package mx.edu.chapingo.siani.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import mx.edu.chapingo.siani.dto.response.SesionPayload;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms}")
    private long jwtExpirationMs;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public long getExpirationMs() {
        return jwtExpirationMs;
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(
                java.util.Base64.getEncoder().encodeToString(jwtSecret.getBytes())
        );
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // =========================================================
    // TOKEN DE SESIÓN — payload completo (pantallas + permisos)
    // =========================================================

    /**
     * Genera un JWT firmado con HMAC-SHA256 que contiene el payload
     * completo de sesión (usuario, rol, pantallas, permisos).
     * Expira en 2 horas.
     *
     * @param payload objeto {@link SesionPayload} con todos los datos
     * @return token JWT firmado como String
     */
    public String generarSesionToken(SesionPayload payload) {
        try {
            // Serializar el payload completo como Map para el claim "sesion"
            @SuppressWarnings("unchecked")
            Map<String, Object> sesionMap = objectMapper.convertValue(payload, Map.class);

            long dosHorasMs = 1000L * 60 * 60 * 2;

            return Jwts.builder()
                    .id(UUID.randomUUID().toString())
                    .issuer("SIANI-UACh")
                    .subject(String.valueOf(payload.getIdUsuario()))
                    .claim("rol", payload.getRol())
                    .claim("usuario", payload.getUsuario())
                    .claim("estatus", payload.getEstatus())
                    .claim("sesion", sesionMap)
                    .issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + dosHorasMs))
                    .signWith(getSigningKey())
                    .compact();

        } catch (Exception e) {
            throw new RuntimeException("Error al generar el token de sesión: " + e.getMessage(), e);
        }
    }

    /**
     * Valida y desencripta un token de sesión generado por {@link #generarSesionToken}.
     * Lanza {@link JwtException} si el token es inválido, expirado o mal firmado.
     *
     * @param token JWT recibido
     * @return objeto {@link SesionPayload} desencriptado
     */
    public SesionPayload validarSesionToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        @SuppressWarnings("unchecked")
        Map<String, Object> sesionMap = (Map<String, Object>) claims.get("sesion");

        return objectMapper.convertValue(sesionMap, SesionPayload.class);
    }
}
