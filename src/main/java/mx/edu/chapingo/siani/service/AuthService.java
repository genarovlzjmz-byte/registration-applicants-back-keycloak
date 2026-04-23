package mx.edu.chapingo.siani.service;

import lombok.RequiredArgsConstructor;
import mx.edu.chapingo.siani.dto.response.*;
import mx.edu.chapingo.siani.domain.Usuario;
import mx.edu.chapingo.siani.dto.request.LoginRequest;
import mx.edu.chapingo.siani.exception.BusinessException;
import mx.edu.chapingo.siani.exception.DuplicateResourceException;
import mx.edu.chapingo.siani.repository.UsuarioRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * PASO 1: Pre-login — valida credenciales (email + CURP + password)
     * pero NO genera JWT aún. Retorna datos básicos del usuario
     * para que el controller envíe el código 2FA.
     */
    @Transactional(readOnly = true)
    public LoginStep1Response preLogin(LoginRequest request) {
        // Verificar que CURP y email correspondan al mismo usuario
        Usuario usuario = usuarioRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BusinessException("Credenciales inválidas"));

        if (!usuario.getCurp().equalsIgnoreCase(request.getCurp())) {
            throw new BusinessException("La CURP no corresponde al correo proporcionado");
        }

        if (!usuario.getActivo()) {
            throw new BusinessException(
                "CANCELASTE TU PARTICIPACIÓN EN EL EXAMEN DE ADMISIÓN 2026 DE LA UACh.");
        }

        // Spring Security valida el password
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        // Credenciales válidas — retornar datos básicos (sin JWT)
        return new LoginStep1Response(usuario.getId(), usuario.getEmail(), usuario.getCurp());
    }

    /**
     * PASO 2: Generar token JWT después de que el código 2FA fue verificado.
     *
     * @param usuarioId ID del usuario ya verificado
     * @return TokenResponse con el JWT
     */
    @Transactional(readOnly = true)
    public TokenResponse generarToken(Long usuarioId) {
        Usuario usuario = usuarioRepository.findById(usuarioId)
                .orElseThrow(() -> new BusinessException("Usuario no encontrado"));

        if (!usuario.getActivo()) {
            throw new BusinessException("La cuenta del usuario está desactivada.");
        }

        String token = jwtService.generateToken(usuario);

        return TokenResponse.builder()
                .token(token)
                .tipo("Bearer")
                .expiresIn(jwtService.getExpirationMs())
                .email(usuario.getEmail())
                .curp(usuario.getCurp())
                .nombre(usuario.getEmail())
                .rol(usuario.getRol())
                .build();
    }

    /**
     * Crear cuenta de acceso (usuario).
     * Paso previo al registro completo del alumno.
     */
    @Transactional
    public Usuario crearUsuario(String curp, String email, String password,
                                 String passwordConfirmacion) {
        // Validar que passwords coincidan
        if (!password.equals(passwordConfirmacion)) {
            throw new BusinessException("Las contraseñas no coinciden");
        }

        // Validar duplicados
        if (usuarioRepository.existsByCurp(curp.toUpperCase())) {
            throw new DuplicateResourceException("Usuario", "CURP", curp);
        }
        if (usuarioRepository.existsByEmail(email.toLowerCase())) {
            throw new DuplicateResourceException("Usuario", "email", email);
        }

        Usuario usuario = Usuario.builder()
                .curp(curp.toUpperCase())
                .email(email.toLowerCase())
                .passwordHash(passwordEncoder.encode(password))
                .rol("ASPIRANTE")
                .activo(true)
                .emailVerificado(false)
                .build();

        return usuarioRepository.save(usuario);
    }

    /**
     * Buscar usuario por email y retornar sus datos con roles.
     */
    @Transactional(readOnly = true)
    public UsuarioConRolResponse findByEmail(String email) {
        Usuario usuario = usuarioRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new BusinessException("No se encontró usuario con el email: " + email));

        // Convertir authorities a lista de strings
        List<String> roles = usuario.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.toList());

        return UsuarioConRolResponse.builder()
                .id(usuario.getId())
                .curp(usuario.getCurp())
                .email(usuario.getEmail())
                .rol(usuario.getRol())
                .activo(usuario.getActivo())
                .emailVerificado(usuario.getEmailVerificado())
                .roles(roles)
                .createdAt(usuario.getCreatedAt())
                .build();
    }

    /**
     * Buscar usuario por ID y retornar sus datos con roles.
     */
    @Transactional(readOnly = true)
    public UsuarioConRolResponse findById(Long id) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new BusinessException("No se encontró usuario con el ID: " + id));

        List<String> roles = usuario.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.toList());

        return UsuarioConRolResponse.builder()
                .id(usuario.getId())
                .curp(usuario.getCurp())
                .email(usuario.getEmail())
                .rol(usuario.getRol())
                .activo(usuario.getActivo())
                .emailVerificado(usuario.getEmailVerificado())
                .roles(roles)
                .createdAt(usuario.getCreatedAt())
                .build();
    }

    // =========================================================
    // TOKEN DE SESIÓN — genera JWT con pantallas y permisos
    // =========================================================

    /**
     * Genera un JWT de sesión completo con el payload:
     * idUsuario, usuario (email), estatus, rol, pantallas y permisos.
     *
     * En producción las pantallas/permisos deben obtenerse de base de datos
     * según el rol del usuario.  Por ahora se construye un ejemplo estático
     * que replica exactamente el JSON solicitado.
     */
    @Transactional(readOnly = true)
    public SesionTokenResponse generarSesionToken(Long usuarioId) {

        Usuario usuario = usuarioRepository.findById(usuarioId)
                .orElseThrow(() -> new BusinessException("No se encontró usuario con el ID: " + usuarioId));

        // --- Pantallas y permisos (ejemplo estático; reemplazar con consulta BD) ---
        List<PantallaInfo> pantallas = new ArrayList<>();

        pantallas.add(PantallaInfo.builder()
                .idPantalla(1)
                .descripcion("Ordenes")
                .permiso(List.of(
                        PermisoInfo.builder().idPermiso(203).descripcion("Consulta_Ordenes").build(),
                        PermisoInfo.builder().idPermiso(256).descripcion("Eliminar_Ordenes").build(),
                        PermisoInfo.builder().idPermiso(247).descripcion("Generar_Ordenes").build()
                ))
                .build());

        pantallas.add(PantallaInfo.builder()
                .idPantalla(12)
                .descripcion("Facturas")
                .permiso(List.of(
                        PermisoInfo.builder().idPermiso(145).descripcion("Consulta_Facturas").build(),
                        PermisoInfo.builder().idPermiso(137).descripcion("Descarga_Facturas").build()
                ))
                .build());

        // --- Payload completo ---
        SesionPayload payload = SesionPayload.builder()
                .codRespuesta(200)
                .exito(true)
                .idUsuario(usuario.getId())
                .usuario(usuario.getEmail())
                .estatus(Boolean.TRUE.equals(usuario.getActivo()) ? "Activo" : "Inactivo")
                .rol(usuario.getRol())
                .pantalla(pantallas)
                .build();

        String token = jwtService.generarSesionToken(payload);

        return SesionTokenResponse.builder()
                .codRespuesta(200)
                .exito(true)
                .token(token)
                .expiresIn(1000L * 60 * 60 * 2)   // 2 horas en ms
                .build();
    }
}
