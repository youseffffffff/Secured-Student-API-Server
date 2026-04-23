using Microsoft.AspNetCore.Mvc;
using StudentApi.DataSimulation;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using StudentApi.DTOs.Auth;
using System.Security.Cryptography;

namespace StudentApi.Controllers
{
    // This controller is responsible for authentication-related actions,
    // such as logging in and issuing JWT tokens (and refresh tokens).
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        // This endpoint handles user login.
        // It verifies credentials and returns:
        // - AccessToken (JWT) for calling secured APIs
        // - RefreshToken for renewing the access token later
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // Step 1: Find the student by email from the in-memory data store.
            // Email acts as the unique login identifier.
            var student = StudentDataSimulation.StudentsList
                .FirstOrDefault(s => s.Email == request.Email);

            // If no student is found with the given email,
            // return 401 Unauthorized without revealing which field was wrong.
            if (student == null)
                return Unauthorized("Invalid credentials");

            // Step 2: Verify the provided password against the stored hash.
            // BCrypt handles hashing and salt internally.
            bool isValidPassword =
                BCrypt.Net.BCrypt.Verify(request.Password, student.PasswordHash);

            // If the password does not match the stored hash,
            // return 401 Unauthorized.
            if (!isValidPassword)
                return Unauthorized("Invalid credentials");

            // Step 3: Create claims that represent the authenticated user's identity.
            // These claims will be embedded inside the JWT.
            var claims = new[]
            {
                // Unique identifier for the student
                new Claim(ClaimTypes.NameIdentifier, student.Id.ToString()),

                // Student email address
                new Claim(ClaimTypes.Email, student.Email),

                // Role (Student or Admin) used later for authorization
                new Claim(ClaimTypes.Role, student.Role)
            };

            // Step 4: Create the symmetric security key used to sign the JWT.
            // This key must match the key used in JWT validation middleware.
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("THIS_IS_A_VERY_SECRET_KEY_123456"));

            // Step 5: Define the signing credentials.
            // This specifies the algorithm used to sign the token.
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Step 6: Create the JWT access token (short-lived).
            // The token includes issuer, audience, claims, expiration, and signature.
            var token = new JwtSecurityToken(
                issuer: "StudentApi",
                audience: "StudentApiUsers",
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(1),
                signingCredentials: creds
            );

            // Step 7: Serialize the JWT into a string.
            // This is what the client will send in the Authorization header.
            var accessToken = new JwtSecurityTokenHandler().WriteToken(token);

            // Step 8: Create refresh token (secure random).
            // Refresh token is used to request a new access token later.
            var refreshToken = GenerateRefreshToken();

            // Step 9: Store refresh token securely (hash + expiry + not revoked).
            // We store the HASH only (never store the raw refresh token).
            student.RefreshTokenHash = BCrypt.Net.BCrypt.HashPassword(refreshToken);
            student.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7);
            student.RefreshTokenRevokedAt = null;

            // Step 10: Return both tokens to the client.
            // AccessToken is used for API calls.
            // RefreshToken is used only for renewing sessions.
            return Ok(new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

        // Generates a cryptographically secure random refresh token.
        // The returned string is safe to send to the client, but should be stored as a hash on the server.
        private static string GenerateRefreshToken()
        {
            var bytes = new byte[64];

            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);

            return Convert.ToBase64String(bytes);
        }


        //refresh endpint
        [HttpPost("refresh")]
        public IActionResult Refresh([FromBody] RefreshRequest request)
        {
            var student = StudentDataSimulation.StudentsList
                .FirstOrDefault(s => s.Email == request.Email);

            if (student == null)
                return Unauthorized("Invalid refresh request");

            if (student.RefreshTokenRevokedAt != null)
                return Unauthorized("Refresh token is revoked");

            if (student.RefreshTokenExpiresAt == null || student.RefreshTokenExpiresAt <= DateTime.UtcNow)
                return Unauthorized("Refresh token expired");

            bool refreshValid = BCrypt.Net.BCrypt.Verify(request.RefreshToken, student.RefreshTokenHash);
            if (!refreshValid)
                return Unauthorized("Invalid refresh token");

            // Issue NEW access token (same claims & signing settings as login)
            var claims = new[]
            {
        new Claim(ClaimTypes.NameIdentifier, student.Id.ToString()),
        new Claim(ClaimTypes.Email, student.Email),
        new Claim(ClaimTypes.Role, student.Role)
    };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("THIS_IS_A_VERY_SECRET_KEY_123456"));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var jwt = new JwtSecurityToken(
                issuer: "StudentApi",
                audience: "StudentApiUsers",
                claims: claims,
                //expires: DateTime.UtcNow.AddMinutes(30),
                expires: DateTime.UtcNow.AddSeconds(1),
                signingCredentials: creds
            );

            var newAccessToken = new JwtSecurityTokenHandler().WriteToken(jwt);

            // Rotation: replace refresh token
            var newRefreshToken = GenerateRefreshToken();
            student.RefreshTokenHash = BCrypt.Net.BCrypt.HashPassword(newRefreshToken);
            student.RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7);
            student.RefreshTokenRevokedAt = null;

            return Ok(new TokenResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        //Logout Endpoint
        [HttpPost("logout")]
        public IActionResult Logout([FromBody] LogoutRequest request)
        {
            var student = StudentDataSimulation.StudentsList
                .FirstOrDefault(s => s.Email == request.Email);

            if (student == null)
                return Ok(); // Do not reveal if user exists

            bool refreshValid = BCrypt.Net.BCrypt.Verify(request.RefreshToken, student.RefreshTokenHash);
            if (!refreshValid)
                return Ok();

            student.RefreshTokenRevokedAt = DateTime.UtcNow;
            return Ok("Logged out successfully");
        }


    }
}
