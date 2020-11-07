using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using DataAccessLayer.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RepositoryLayer.Repositories.Interface;
using ServiceLayer.Person;
using WebAPI.Models;
using WebAPI.Models.Post;

namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PersonController : ControllerBase
    {
        private readonly IMapper mapper;
        private readonly IPersonService personService;
        private IUnitOfWork unitOfWork;
        private UserManager<ApplicationUser> _userManager;

        public PersonController(IMapper mapper, IPersonService personService, IUnitOfWork unitOfWork,UserManager<ApplicationUser> userManager)
        {
            this.personService = personService;
            this.mapper = mapper;
            this.unitOfWork = unitOfWork;
            _userManager = userManager;
        }
        [HttpPost]
        [Authorize]
        [Route("CreatePost")]
        public async Task<IActionResult> CreatePost(CreatePostResource postResource)
        {
            var apiResponse = new APIMessage();
            if (!ModelState.IsValid)
            {
                apiResponse.bit = false;
                apiResponse.message = ModelState.ToString();
                return BadRequest(apiResponse);
            }
                
            var post = mapper.Map<CreatePostResource, Post>(postResource);
            try
            {
                var user = await _userManager.GetUserAsync(User);
                var person = personService.GetPerson(user.Id);
                post.Person = person;
                post.PersonId = person.Id;
                personService.AddPost(post);
                await unitOfWork.CompleteAsync();
                apiResponse.bit = true;
                apiResponse.message = "your post has been added";
                return Ok(apiResponse);
            }
            catch (Exception)
            {
                apiResponse.bit = false;
                apiResponse.message = "cannot add post";
                return BadRequest(apiResponse);
            }        
        }
        [HttpDelete]
        [Authorize]
        [Route("DeletePost")]
        public async Task<IActionResult> DeletePost(int PostId)
        {
            var apiResponse = new APIMessage();
            if (!ModelState.IsValid)
            {
                apiResponse.bit = false;
                apiResponse.message = ModelState.ToString();
                return BadRequest(apiResponse);
            }
            try
            {
                var user = await _userManager.GetUserAsync(User);
                var person = personService.GetPerson(user.Id);
                if (personService.DeletePost(person.Id, PostId))
                {
                    await unitOfWork.CompleteAsync();
                    apiResponse.bit = true;
                    apiResponse.message = "your post has been deleted";
                    return Ok(apiResponse);
                }
                else
                {
                    apiResponse.bit = false;
                    apiResponse.message = "cannot delete post";
                    return NotFound(apiResponse);
                }
            }
            catch (Exception)
            {
                apiResponse.bit = false;
                apiResponse.message = "cannot Delete post";
                return BadRequest(apiResponse);
            }
        }
        [HttpPost]
        [Authorize]
        [Route("ReactPost")]
        public async Task<IActionResult> ReactPost(ReactResource reactResource)
        {
            var apiResponse = new APIMessage();
            if (!ModelState.IsValid)
            {
                apiResponse.bit = false;
                apiResponse.message = ModelState.ToString();
                return BadRequest(apiResponse);
            }


            var react = mapper.Map<ReactResource, React>(reactResource);

            try
            {
                var user = await _userManager.GetUserAsync(User);
                var person = personService.GetPerson(user.Id);
                react.Person = person;
                react.PersonId = person.Id;
                apiResponse.bit = true;
                apiResponse.message = personService.ReactOnPost(react);
                await unitOfWork.CompleteAsync();
                return Ok(apiResponse);
            }
            catch (Exception)
            {
                apiResponse.bit = false;
                apiResponse.message = "cannot add react";
                return BadRequest(apiResponse);
            }
        }
        [HttpPost]
        [Authorize]
        [Route("AddFriend")]
        public async Task<IActionResult> AddFriend(string userName)
        {
            var apiResponse = new APIMessage();
            if (!ModelState.IsValid)
            {
                apiResponse.bit = false;
                apiResponse.message = ModelState.ToString();
                return BadRequest(apiResponse);
            }

            try
            {
                var user = await _userManager.GetUserAsync(User);
                var person = personService.GetPerson(user.Id);
                var userFriend = await _userManager.FindByNameAsync(userName);
                if (userFriend == null)
                {
                    apiResponse.bit = false;
                    apiResponse.message = "cannot find user";
                    return NotFound(apiResponse);
                }
                personService.AddFriend(person.Id, userFriend.Person.Id);
                await unitOfWork.CompleteAsync();
                apiResponse.bit = true;
                apiResponse.message = "your and " + userFriend.UserName + " are now friends";
                return Ok(apiResponse);
            }
            catch (Exception)
            {
                apiResponse.bit = false;
                apiResponse.message = "cannot add friend";
                return BadRequest(apiResponse);
            }
        }
        [HttpGet]
        [Authorize]
        [Route("GetAllPosts")]
        public async Task<IActionResult> GetAllPosts()
        {
            var apiResponse = new APIData<PostResource>();
            try
            {
                var user = await _userManager.GetUserAsync(User);
                var person = personService.GetPerson(user.Id);
                var posts = personService.GetAllPosts(person.Id);
                apiResponse.bit = true;
                apiResponse.data = mapper.Map<List<Post>, List<PostResource>>(posts);
                return Ok(apiResponse);
            }
            catch (Exception)
            {
                apiResponse.bit = false;
                apiResponse.data = new List<PostResource>();
                return BadRequest(apiResponse);
            }
        }
    }
}
