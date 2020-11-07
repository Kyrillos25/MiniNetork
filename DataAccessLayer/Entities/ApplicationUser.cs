using Microsoft.AspNetCore.Identity;

namespace DataAccessLayer.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public int PersonId { get; set; }
        public Person Person { get; set; }
    }
}
