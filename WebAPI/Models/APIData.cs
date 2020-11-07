using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPI.Models
{
    public class APIData<T> : APIResponse
    {
        public List<T> data { get; set; }
    }
}
