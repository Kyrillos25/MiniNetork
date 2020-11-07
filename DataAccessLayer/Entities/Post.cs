using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer.Entities
{
    public class Post : BaseEntity
    {
        public string Text { get; set; }
        public string ImagePath { get; set; }
        public int PersonId { get; set; }
        public virtual Person Person { get; set; }
        public ICollection<React> Reacts { get; set; }
    }
}
