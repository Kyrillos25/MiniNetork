using DataAccessLayer.Entities;
using RepositoryLayer.Repositories.Interface;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ServiceLayer.Person
{
    public class PersonService : IPersonService
    {
        private IPersonRepository personRepository;
        private IPostRepository postRepository;

        public PersonService(IPostRepository postRepository, IPersonRepository personRepository)
        {
            this.postRepository = postRepository;
            this.personRepository = personRepository;
        }

        public void AddFriend(int personId, int FriendId)
        {
            personRepository.AddFriend(personId,FriendId);
        }

        public void AddPerson(ApplicationUser applicationUser)
        {
            personRepository.CreatePerson(applicationUser);
        }

        public void AddPost(Post post)
        {
           postRepository.Add(post);
        }

        public bool DeletePost(int personId, int PostId)
        {
            return postRepository.DeletePost(personId, PostId);
        }

        public List<Post> GetAllPosts(int personId)
        {
            return postRepository.GetAllPosts(personId);
        }

        public DataAccessLayer.Entities.Person GetPerson(string userId)
        {
            return personRepository.GetPersonByUserId(userId);
        }

        public string ReactOnPost(React react)
        {
            return postRepository.ReactOnPost(react);
        }
    }
}
