using DataAccessLayer.Config;
using DataAccessLayer.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Text;

namespace RepositoryLayer
{
    public class MiniNetworkDBContext : IdentityDbContext<ApplicationUser>
    {
        public MiniNetworkDBContext(DbContextOptions<MiniNetworkDBContext> options)
        : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            new PersonConfig(modelBuilder.Entity<Person>());
            new PostConfig(modelBuilder.Entity<Post>());
            new FriendshipConfig(modelBuilder.Entity<Friendship>());
            new ReactConfig(modelBuilder.Entity<React>());
            modelBuilder.Entity<React>().HasKey(r =>
                new { r.PersonId, r.PostId });
            modelBuilder.Entity<Friendship>().HasKey(f =>
                new { f.PersonId, f.FriendId });
        }
    }
}
