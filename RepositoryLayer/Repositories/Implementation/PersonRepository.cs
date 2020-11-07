using DataAccessLayer.Entities;
using RepositoryLayer.Repositories.Interface;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RepositoryLayer.Repositories.Implementation
{
    public class PersonRepository : Repository<Person>, IPersonRepository
    {
        private readonly MiniNetworkDBContext context;
        public PersonRepository(MiniNetworkDBContext context) : base(context)
        {
            this.context = context;
        }

        public void AddFriend(int personId, int friendId)
        {
            Friendship friendship = new Friendship() { PersonId = personId, FriendId = friendId };
            context.Set<Friendship>().Add(friendship);
        }

        public void CreatePerson(ApplicationUser applicationUser)
        {
            Person person = new Person();
            person.User = applicationUser;
            person.UserId = applicationUser.Id;
            context.Set<Person>().Add(person);
            context.SaveChanges();
        }

        public Person GetPersonByUserId(string userId)
        {
            List<Person> persons = context.Set<Person>().ToList();
           return persons.Where(p => p.UserId == userId).FirstOrDefault();
        }
    }
}
