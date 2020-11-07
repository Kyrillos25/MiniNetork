using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPI.Models.Post
{
    public class CreatePostResource
    {
        public string Text { get; set; }
        public string ImagePath { get; set; }
    }
}
