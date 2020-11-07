using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPI.Models.Post
{
    public class PostResource : CreatePostResource
    {
        public int Id { get; set; }
        
    }
}
