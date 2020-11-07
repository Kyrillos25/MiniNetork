using DataAccessLayer.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPI.Models.Post
{
    public class ReactResource
    {
        public int PostId { get; set; }
        public int PersonId { get; set; }
        public ReactValue React { get; set; }
    }
}
