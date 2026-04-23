package mx.edu.chapingo.siani.dto.response;

import lombok.*;

import java.util.List;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class PantallaInfo {
    private Integer idPantalla;
    private String descripcion;
    private List<PermisoInfo> permiso;
}

