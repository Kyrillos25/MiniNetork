using DataAccessLayer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Text;

namespace DataAccessLayer.Config
{
    public class PersonConfig
    {
        public PersonConfig(EntityTypeBuilder<Person> entityBuilder)
        {
            entityBuilder.HasKey(p => p.Id);
            entityBuilder.HasMany(p => p.Posts).WithOne(p => p.Person).HasForeignKey(x => x.Id);
            entityBuilder.HasOne(p => p.User).WithOne(p => p.Person).HasForeignKey<Person>(x=>x.UserId).OnDelete(DeleteBehavior.Restrict);
        }
    }
}
