package mx.edu.chapingo.siani.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import mx.edu.chapingo.siani.dto.request.LoginRequest;
import mx.edu.chapingo.siani.dto.response.*;
import mx.edu.chapingo.siani.service.AuthService;
import mx.edu.chapingo.siani.service.CodigoVerificacionService;
import mx.edu.chapingo.siani.service.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Autenticación", description = "Login con verificación por email")
public class AuthController {

    private final AuthService authService;
    private final CodigoVerificacionService codigoService;
    private final JwtService jwtService;

    // ============================================================
    // STEP 1: Login con password → genera y envía código por email
    // ============================================================

    @Operation(
            summary = "Paso 1: Login con credenciales",
            description = "Valida email + curp + password. Si es correcto, genera un código de 6 dígitos "
                    + "y lo envía al email del usuario. NO retorna JWT aún."
    )
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginStep1Response>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        // 1. Validar credenciales (email + curp + password)
        //    Esto lanza excepción si las credenciales son incorrectas
        LoginStep1Response preAuth = authService.preLogin(request);

        // 2. Generar código y enviarlo por email
        String clientIp = httpRequest.getRemoteAddr();
        codigoService.generarYEnviar(preAuth.getUsuarioId(), request.getEmail(), clientIp);

        return ResponseEntity.ok(ApiResponse.ok(
                "Credenciales válidas. Se envió un código de verificación a tu email.",
                preAuth));
    }

    // ============================================================
    // STEP 2: Verificar código → retorna JWT
    // ============================================================

    @Operation(
            summary = "Paso 2: Verificar código de email",
            description = "Valida el código de 6 dígitos enviado por email. "
                    + "Si es correcto, retorna el token JWT."
    )
    @PostMapping("/verify-code")
    public ResponseEntity<ApiResponse<SesionTokenResponse>> verifyCode(
            @Valid @RequestBody VerifyCodeRequest request) {

        // 1. Verificar el código
        boolean valido = codigoService.verificarCodigo(request.getUsuarioId(), request.getCodigo());

        if (!valido) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Código incorrecto. Intenta de nuevo."));
        }

        // 2. Código válido → generar token de sesión completo (con pantallas y permisos)
        SesionTokenResponse resp = authService.generarSesionToken(request.getUsuarioId());

        return ResponseEntity.ok(ApiResponse.ok("Verificación exitosa", resp));
    }

    // ============================================================
    // REENVIAR CÓDIGO
    // ============================================================

    @Operation(
            summary = "Reenviar código de verificación",
            description = "Genera un nuevo código y lo envía al email. Invalida el anterior."
    )
    @PostMapping("/resend-code")
    public ResponseEntity<ApiResponse<Void>> resendCode(
            @Valid @RequestBody ResendCodeRequest request,
            HttpServletRequest httpRequest) {

        String clientIp = httpRequest.getRemoteAddr();
        codigoService.generarYEnviar(request.getUsuarioId(), request.getEmail(), clientIp);

        return ResponseEntity.ok(ApiResponse.ok(
                "Se envió un nuevo código de verificación a tu email.", null));
    }

    // ============================================================
    // BUSCAR USUARIO POR EMAIL (con roles)
    // ============================================================

    @Operation(
            summary = "Buscar usuario por email",
            description = "Busca un usuario por su email y retorna sus datos junto con los roles asignados."
    )
    @GetMapping("/find-by-email")
    public ResponseEntity<ApiResponse<UsuarioConRolResponse>> findByEmail(
            @RequestParam @NotBlank @Email String email) {

        UsuarioConRolResponse usuario = authService.findByEmail(email);

        return ResponseEntity.ok(ApiResponse.ok("Usuario encontrado", usuario));
    }

    // ============================================================
    // BUSCAR USUARIO POR ID (con roles)
    // ============================================================

    @Operation(
            summary = "Buscar usuario por ID",
            description = "Busca un usuario por su ID y retorna sus datos junto con los roles asignados."
    )
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<UsuarioConRolResponse>> findById(
            @PathVariable Long id) {

        UsuarioConRolResponse usuario = authService.findById(id);

        return ResponseEntity.ok(ApiResponse.ok("Usuario encontrado", usuario));
    }

    // ============================================================
    // GENERAR TOKEN DE SESIÓN (con pantallas y permisos)
    // ============================================================

    @Operation(
            summary = "Generar token de sesión completo",
            description = "Genera un JWT firmado con HMAC-SHA256 que contiene el payload completo "
                    + "de sesión: idUsuario, usuario, estatus, rol, pantallas y permisos. "
                    + "Expira en 2 horas. El token puede ser validado/desencriptado por otro "
                    + "servicio Java usando el endpoint /auth/validar-sesion-token."
    )
    @GetMapping("/sesion-token/{id}")
    public ResponseEntity<ApiResponse<SesionTokenResponse>> generarSesionToken(
            @PathVariable Long id) {

        SesionTokenResponse resp = authService.generarSesionToken(id);
        return ResponseEntity.ok(ApiResponse.ok("Token de sesión generado", resp));
    }

    // ============================================================
    // VALIDAR / DESENCRIPTAR TOKEN DE SESIÓN
    // ============================================================

    @Operation(
            summary = "Validar y desencriptar token de sesión",
            description = "Recibe el JWT generado por /auth/sesion-token/{id}, valida la firma HMAC-SHA256 "
                    + "y la expiración, y retorna el payload completo desencriptado "
                    + "(idUsuario, usuario, rol, pantallas, permisos)."
    )
    @PostMapping("/validar-sesion-token")
    public ResponseEntity<ApiResponse<SesionPayload>> validarSesionToken(
            @Valid @RequestBody ValidarTokenRequest request) {

        try {
            SesionPayload payload = jwtService.validarSesionToken(request.getToken());
            return ResponseEntity.ok(ApiResponse.ok("Token válido", payload));
        } catch (JwtException e) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Token inválido o expirado: " + e.getMessage()));
        }
    }

    // ============================================================
    // DTOs internos (request)
    // ============================================================

    @Getter @Setter
    public static class ValidarTokenRequest {
        @NotBlank(message = "El token no puede estar vacío")
        private String token;
    }


    @Getter
    @Setter
    public static class VerifyCodeRequest {
        @jakarta.validation.constraints.NotNull
        private Long usuarioId;

        @NotBlank
        @Size(min = 6, max = 6, message = "El código debe ser de 6 dígitos")
        private String codigo;
    }

    @Getter @Setter
    public static class ResendCodeRequest {
        @jakarta.validation.constraints.NotNull
        private Long usuarioId;

        @NotBlank @Email
        private String email;
    }
}
