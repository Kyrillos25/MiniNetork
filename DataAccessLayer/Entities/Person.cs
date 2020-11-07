using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer.Entities
{
    public class Person : BaseEntity
    {
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
        public ICollection<Friendship> Friends { get; set; }
        public ICollection<Post> Posts { get; set; }
    }
}
