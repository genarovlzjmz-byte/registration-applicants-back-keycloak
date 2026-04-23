package mx.edu.chapingo.siani.dto.response;

import lombok.*;

import java.util.List;

/**
 * Respuesta del endpoint /auth/sesion-token.
 * Contiene el token JWT firmado con el payload completo de sesión
 * (usuario, rol, pantallas y permisos).
 */
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SesionTokenResponse {

    /** Código de respuesta HTTP semántico embebido en el body */
    private int codRespuesta;

    /** Indica si la operación fue exitosa */
    private boolean exito;

    /** Token JWT firmado que contiene todo el payload de sesión */
    private String token;

    /** Tiempo de expiración en milisegundos (para info del cliente) */
    private long expiresIn;
}

