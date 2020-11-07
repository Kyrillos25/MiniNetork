using DataAccessLayer.Entities;
using System;
using System.Collections.Generic;
using System.Text;

namespace RepositoryLayer.Repositories.Interface
{
    public interface IPersonRepository : IRepository<Person>
    {
        void CreatePerson(ApplicationUser applicationUser);
        Person GetPersonByUserId(string userId);
        void AddFriend(int personId, int FriendId);
    }
}
