using DataAccessLayer.Entities;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace ServiceLayer.Person
{
    public interface IPersonService
    {
        void AddPerson(ApplicationUser applicationUser);
        void AddFriend(int personId, int FriendId);
        void AddPost(Post post);
        bool DeletePost(int personId, int PostId);
        string ReactOnPost(React react);
        DataAccessLayer.Entities.Person GetPerson(string userId);
        List<Post> GetAllPosts(int personId);
    }
}
