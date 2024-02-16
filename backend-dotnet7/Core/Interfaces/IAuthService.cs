using backend_dotnet7.Core.Dtos.Auth;
using backend_dotnet7.Core.Dtos.General;
using System.Security.Claims;

namespace backend_dotnet7.Core.Interfaces
{
    public interface IAuthService
    {
        Task<GeneralServiceResponseDto> SeedRoleAsync();
        Task<GeneralServiceResponseDto> RegisterAsync(RegisterDto registerDto);
        Task<LoginServiceResponceDto?> LoginAsync(LoginDto loginDto);
        Task<GeneralServiceResponseDto> UpdateRoleAsync(ClaimsPrincipal User, UpdateRoleDto updateRoleDto);
        Task<LoginServiceResponceDto> MeAsync(MeDto meDto); 
        Task<IEnumerable<UserInfoResult>> GetUserListAsync(); 
        Task<UserInfoResult?> GetUserDetailsByUserNameAsyncs(string userName);
        Task<IEnumerable<string>> GetUsernameListAsync();
    }
}
