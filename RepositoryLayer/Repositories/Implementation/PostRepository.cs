using DataAccessLayer.Entities;
using Microsoft.EntityFrameworkCore;
using RepositoryLayer.Repositories.Interface;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RepositoryLayer.Repositories.Implementation
{
    public class PostRepository : Repository<Post>, IPostRepository
    {
        private readonly MiniNetworkDBContext context;
        public PostRepository(MiniNetworkDBContext context) : base(context)
        {
            this.context = context;
        }

        public bool DeletePost(int personId, int postId)
        {
           var post = context.Set<Post>().Where(p => p.PersonId == personId && p.Id == postId).FirstOrDefault();
            if (post != null)
            {
                context.Set<Post>().Remove(post);
                return true;
            }
            return false;
        }

        public List<Post> GetAllPosts(int personId)
        {
            var posts = context.Set<Post>().Where(p => p.PersonId == personId).ToList();
            var person = context.Set<Person>().Where(p => p.Id == personId).Include(p=>p.Friends).FirstOrDefault();
            foreach (var friendship in person.Friends)
            {
                var friend = context.Set<Person>().Where(p => p.Id == friendship.FriendId).Include(p => p.Friends).Include(p => p.Posts).FirstOrDefault();
                if (friend.Friends.Where(f=>f.FriendId == personId).FirstOrDefault() != null)
                {
                    posts.AddRange(friend.Posts);
                }
            }
            return posts;
        }

        public string ReactOnPost(React react)
        {
            var freact = context.Set<React>().Where(r => r.PersonId == react.PersonId && r.PostId == react.PostId).FirstOrDefault();
            if (freact != null)
            {
                context.Set<React>().Remove(freact);
                return "your react has been removed";
            }
            else
            {
                context.Set<React>().Add(react);
                return "your react has been added";
            }
        }
    }
}
