package utilities;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtService {

    private static final byte[] SECRET_KEY =
            "gestion-options-esprit-secret-key-change-me-0123456789-abcdefghijklmnopqrstuvwxyz"
                    .getBytes(StandardCharsets.UTF_8);

    public static final long ACCESS_MINUTES = 15L;

    // ===== Generation =====
    public static String generateAccessToken(String username, String issuer) {
        long duree = ACCESS_MINUTES * 60 * 1000;
        return buildToken(username, issuer, "access", duree, null);
    }

    private static String buildToken(String username, String issuer, String type,
                                     long dureeMillis, String jti) {
        long now = System.currentTimeMillis();
        JwtBuilder builder = Jwts.builder()
                .setSubject(username)
                .setIssuer(issuer)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + dureeMillis))
                .claim("type", type);
        if (jti != null) {
            builder.setId(jti);
        }
        return builder.signWith(SignatureAlgorithm.HS512, SECRET_KEY).compact();
    }

    // ===== Validation =====
    private static Claims parse(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    public static Claims validateAccessToken(String token) {
        Claims claims = parse(token);
        if (!"access".equals(claims.get("type"))) {
            throw new IllegalArgumentException("Ce jeton n'est pas un access token");
        }
        return claims;
    }

    // ===== Part C: refresh token =====
    public static final long REFRESH_DAYS = 7L;

    private static final Map<String, String> REFRESH_STORE = new ConcurrentHashMap<>();

    public static String generateRefreshToken(String username, String issuer) {
        String jti = UUID.randomUUID().toString();
        long duree = REFRESH_DAYS * 24 * 60 * 60 * 1000;
        String token = buildToken(username, issuer, "refresh", duree, jti);
        REFRESH_STORE.put(jti, username);
        return token;
    }

    public static String useRefreshToken(String token) {
        Claims claims = parse(token);
        if (!"refresh".equals(claims.get("type"))) {
            throw new IllegalArgumentException("Ce jeton n'est pas un refresh token");
        }
        if (REFRESH_STORE.remove(claims.getId()) == null) {
            throw new IllegalArgumentException("Refresh token révoqué ou déjà utilisé");
        }
        return claims.getSubject();
    }

    public static void revokeRefreshToken(String token) {
        try {
            REFRESH_STORE.remove(parse(token).getId());
        } catch (Exception e) {
            // token already invalid or expired: nothing to revoke
        }
    }
}