using DataAccessLayer.Entities;
using System;
using System.Collections.Generic;
using System.Text;

namespace RepositoryLayer.Repositories.Interface
{
    public interface IPostRepository : IRepository<Post>
    {
        string ReactOnPost(React react);
        bool DeletePost(int personId, int PostId);
        List<Post> GetAllPosts(int personId);
    }
}
