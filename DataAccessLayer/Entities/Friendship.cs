using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer.Entities
{
    public class Friendship
    {
        public int PersonId { get; set; }
        public int FriendId { get; set; }

        public virtual Person Person { get; set; }
        public virtual Person Friend { get; set; }
    }
}
