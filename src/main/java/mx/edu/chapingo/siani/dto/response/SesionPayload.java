package mx.edu.chapingo.siani.dto.response;

import lombok.*;

import java.util.List;

/**
 * Payload completo de sesión que se embebe dentro del JWT como claim "sesion".
 * Estructura compatible con el JSON de ejemplo solicitado.
 */
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SesionPayload {

    private int codRespuesta;
    private boolean exito;
    private Long idUsuario;
    private String usuario;
    private String estatus;
    private String rol;
    private List<PantallaInfo> pantalla;
}

