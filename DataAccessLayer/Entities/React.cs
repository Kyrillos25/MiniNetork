using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer.Entities
{
    public enum ReactValue
    {
        Like = 1,
        Love = 2
    }
    public class React
    {
        public int PostId { get; set; }
        public int PersonId { get; set; }
        public ReactValue ReactVal { get; set; }

        public virtual Post Post { get; set; }
        public virtual Person Person { get; set; }
    }
}
