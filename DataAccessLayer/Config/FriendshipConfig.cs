using DataAccessLayer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer.Config
{
    public class FriendshipConfig
    {
        public FriendshipConfig(EntityTypeBuilder<Friendship> entityBuilder)
        {
            entityBuilder.HasKey(f =>
                new { f.PersonId, f.FriendId });
            entityBuilder.HasOne<Person>(f => f.Person).WithMany(fr => fr.Friends).OnDelete(DeleteBehavior.Restrict);//.HasForeignKey(p => p.PersonId).HasForeignKey(p=>p.FriendId);
            //entityBuilder.HasOne<Person>(f => f.Friend).WithMany(fr => fr.Friends).OnDelete(DeleteBehavior.Restrict);

        }
    }
}
