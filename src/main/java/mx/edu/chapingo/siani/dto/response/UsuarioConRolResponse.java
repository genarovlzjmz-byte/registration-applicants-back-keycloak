package mx.edu.chapingo.siani.dto.response;

import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UsuarioConRolResponse {
    private Long id;
    private String curp;
    private String email;
    private String rol;
    private Boolean activo;
    private Boolean emailVerificado;
    private List<String> roles;
    private LocalDateTime createdAt;
}

