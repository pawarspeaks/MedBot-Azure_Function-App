using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace TokenGenerator
{
    public static class TokenGenerator
    {
        [FunctionName("GenereratorFunction")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Environment.GetEnvironmentVariable("WEBCHAT_SECRET"));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                HttpResponseMessage response = await client.PostAsync("https://directline.botframework.com/v3/directline/tokens/generate", null);

                var token = GenerateToken(JsonConvert.DeserializeObject<DirectLinePayload>(await response.Content.ReadAsStringAsync()));
                return new OkObjectResult(token);
            }
        }

        private static string GenerateToken(DirectLinePayload payload, int expireMinutes = 200)
        {
            var symmetricKey = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("APP_SECRET"));
            var tokenHandler = new JwtSecurityTokenHandler();

            var now = DateTime.UtcNow;
            var claims = new ClaimsIdentity(new[]
                {
                    new Claim("userId", Guid.NewGuid().ToString()),
                    new Claim("userName", "you"),
                    new Claim("connectorToken", payload.token)
                });
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claims,
                Expires = now.AddMinutes(Convert.ToInt32(expireMinutes)),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var stoken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(stoken);

            return token;
        }
    }
    
    public class DirectLinePayload
    {
        public string conversationId { get; set; }
        public string token { get; set; }
        public int expires_in { get; set; }
    }
}
