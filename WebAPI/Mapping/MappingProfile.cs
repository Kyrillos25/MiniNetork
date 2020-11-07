using AutoMapper;
using DataAccessLayer.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebAPI.Models.Post;

namespace WebAPI.Mapping
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<Post, PostResource>();
            CreateMap<Post, CreatePostResource > ();




            CreateMap<PostResource, Post>();
            CreateMap<CreatePostResource, Post>();
            CreateMap<List<PostResource>, List<Post>>();
            CreateMap<ReactResource, React>();
        }
    }
}
